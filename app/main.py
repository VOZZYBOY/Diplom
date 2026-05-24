"""
LLM Filter Service — FastAPI application.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import load_config
from app.core.ensemble import EnsembleEngine
from app.core.types import (
    FilterRequest,
    FilterResponse,
    HealthResponse,
    ModelHealth,
    ToolFilterRequest,
)
from app.guards.code_guard import analyze_code
from app.models.behavioral import BehavioralModel
from app.models.pattern import PatternModel
from app.models.semantic import SemanticModel
from app.rails.tool_rail import tool_rail

logger = logging.getLogger("llm-filter")


def create_app() -> FastAPI:
    config = load_config()
    logging.basicConfig(level=getattr(logging, config.logging.level.upper(), logging.INFO))

    engine = EnsembleEngine(config)
    engine.register(BehavioralModel())
    engine.register(PatternModel())

    llm_config = None
    if config.semantic.enabled and config.semantic.api_key:
        engine.register(SemanticModel(config.semantic))
        llm_config = config.semantic
        logger.info("Semantic model registered (%s)", config.semantic.model)
    elif config.semantic.enabled:
        logger.warning("Semantic model enabled but no API key — running without LLM")
        engine.llm_available = False

    app = FastAPI(
        title="LLM Filter Service",
        description="Multi-Model Ensemble Filter for prompt injection protection",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.post("/v1/filter", response_model=FilterResponse)
    async def filter_request(request: FilterRequest) -> FilterResponse:
        if not request.messages:
            raise HTTPException(400, "messages field is required")

        result = await engine.analyze(request)

        if result.verdict.value == "block" and config.logging.log_blocked:
            logger.info("BLOCKED | score=%.2f | %s | %s", result.risk_score, result.categories, request.session_id)
        elif result.verdict.value == "review" and config.logging.log_review:
            logger.info("REVIEW  | score=%.2f | %s | %s", result.risk_score, result.categories, request.session_id)

        return result

    @app.post("/v1/filter/tool", response_model=FilterResponse)
    async def filter_tool(request: ToolFilterRequest) -> FilterResponse:
        if not request.tool_name or not request.messages:
            raise HTTPException(400, "tool_name and messages are required")

        allowed, result = await tool_rail(
            check=engine.analyze,
            tool_name=request.tool_name,
            tool_args=request.tool_args,
            messages=[m.model_dump() for m in request.messages],
            session_id=request.session_id,
            llm_config=llm_config,
            trust_level=request.trust_level,
        )

        if result:
            return result

        return FilterResponse(
            verdict="allow",
            risk_score=0.0,
            scores={"semantic": None, "behavioral": 0.0, "pattern": 0.0},
            weights={"semantic": 0.4, "behavioral": 0.3, "pattern": 0.3},
            categories=[],
            reasoning="Tool allowed — no sensitive tool or threats detected.",
            latency_ms=0,
        )

    @app.post("/v1/filter/code", response_model=FilterResponse)
    async def filter_code(request: ToolFilterRequest) -> FilterResponse:
        """Dedicated Code Guard endpoint — analyze code before execution."""
        if not request.tool_name:
            raise HTTPException(400, "tool_name is required")

        code = request.tool_args.get("code") or request.tool_args.get("content") or ""
        if not code:
            raise HTTPException(400, "code or content field required in tool_args")

        return await analyze_code(
            code=str(code),
            tool_name=request.tool_name,
            tool_args=request.tool_args,
            llm_config=llm_config,
        )

    @app.get("/v1/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            models={
                "semantic": ModelHealth(available=engine.llm_available, latency_ms=0),
                "behavioral": ModelHealth(available=True, latency_ms=0),
                "pattern": ModelHealth(available=True, latency_ms=0),
                "code_guard": ModelHealth(available=engine.llm_available, latency_ms=0),
            },
            version="1.0.0",
        )

    @app.get("/v1/config")
    async def get_config() -> dict:
        safe = config.model_dump()
        if safe.get("semantic", {}).get("api_key"):
            safe["semantic"]["api_key"] = "***"
        return safe

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    cfg = load_config()
    uvicorn.run(
        "app.main:app",
        host=cfg.server.host,
        port=cfg.server.port,
        reload=False,
    )
