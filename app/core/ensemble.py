"""
Ensemble Engine — orchestrates models in parallel and aggregates results.
"""

from __future__ import annotations

import time

from app.core.aggregator import adjust_weights, aggregate_scores
from app.core.config import FilterConfig
from app.core.types import (
    DetectorOutput,
    FilterRequest,
    FilterResponse,
    ModelName,
    ModelScores,
    ModelWeights,
    Verdict,
)
from app.utils.redaction import redact_sensitive_text


class EnsembleEngine:
    def __init__(self, config: FilterConfig) -> None:
        self.config = config
        self._models: dict[ModelName, object] = {}
        self.llm_available = True

    def register(self, model: object) -> None:
        self._models[model.name] = model  # type: ignore[attr-defined]

    async def analyze(self, request: FilterRequest) -> FilterResponse:
        start = time.monotonic()

        base_weights = self._base_weights()
        weights = adjust_weights(
            base_weights,
            llm_available=self.llm_available,
            message_length=self._message_length(request),
            direction=request.direction.value,
        )

        enabled = self._enabled_models(request.models)
        results = await self._run_models(enabled, request)

        block_t = (
            request.thresholds.block
            if request.thresholds and request.thresholds.block
            else self.config.thresholds.block
        )
        review_t = (
            request.thresholds.review
            if request.thresholds and request.thresholds.review
            else self.config.thresholds.review
        )

        risk_score, verdict = aggregate_scores(results, weights, block_t, review_t)

        scores = ModelScores(semantic=None, behavioral=None, pattern=None)
        for r in results:
            setattr(scores, r.model_name.value, r.score)

        categories = list({c for r in results for c in r.categories})
        reasoning = " | ".join(f"[{r.model_name.value}] {r.reasoning}" for r in results if r.reasoning)
        user_message = "Запрос заблокирован: обнаружена угроза безопасности." if verdict == Verdict.BLOCK else None

        sanitized_content = None
        redactions: list[str] = []
        if request.direction.value == "output":
            output_text = " ".join(m.content for m in request.messages if m.role == "assistant")
            sanitized_content, found_redactions = redact_sensitive_text(output_text)
            if found_redactions:
                redactions = [f"{item.kind}:{item.count}" for item in found_redactions]
            else:
                sanitized_content = None

        elapsed_ms = int((time.monotonic() - start) * 1000)

        return FilterResponse(
            verdict=verdict,
            risk_score=round(risk_score, 4),
            scores=scores,
            weights=ModelWeights(
                semantic=round(weights[ModelName.SEMANTIC], 3),
                behavioral=round(weights[ModelName.BEHAVIORAL], 3),
                pattern=round(weights[ModelName.PATTERN], 3),
            ),
            categories=categories,
            reasoning=reasoning,
            user_message=user_message,
            latency_ms=elapsed_ms,
            sanitized_content=sanitized_content,
            redactions=redactions,
        )

    def _base_weights(self) -> dict[ModelName, float]:
        return {
            ModelName.SEMANTIC: self.config.semantic.weight,
            ModelName.BEHAVIORAL: self.config.behavioral.weight,
            ModelName.PATTERN: self.config.pattern.weight,
        }

    def _enabled_models(self, requested: list[ModelName] | None) -> list[object]:
        models = []
        for name, model in self._models.items():
            if requested and name not in requested:
                continue
            if name == ModelName.SEMANTIC and not self.llm_available:
                continue
            models.append(model)
        return models

    async def _run_models(self, models: list[object], request: FilterRequest) -> list[DetectorOutput]:
        import asyncio

        tasks = [model.analyze(request) for model in models]  # type: ignore[union-attr]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        outputs = []
        for model, result in zip(models, results):
            if isinstance(result, Exception):
                outputs.append(
                    DetectorOutput(
                        model_name=model.name,  # type: ignore[attr-defined]
                        score=0.5,
                        confidence=0.1,
                        categories=[],
                        reasoning=f"Model error: {result}",
                        latency_ms=0,
                    )
                )
            else:
                outputs.append(result)
        return outputs

    def _message_length(self, request: FilterRequest) -> int:
        return sum(len(m.content) for m in request.messages if m.role == "user")
