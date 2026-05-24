"""
Semantic Model — LLM-as-judge with SGR (Schema-Guided Reasoning).
"""

from __future__ import annotations

import time
import json
import re

from openai import AsyncOpenAI

from app.models.base import BaseDetectorModel
from app.core.config import SemanticModelConfig
from app.core.types import DetectorOutput, FilterRequest, ModelName, RiskCategory
from app.schemas.risk import SYSTEM_PROMPT, RiskAssessment, build_user_prompt


class SemanticModel(BaseDetectorModel):
    def __init__(self, config: SemanticModelConfig) -> None:
        self._config = config
        self._client = AsyncOpenAI(
            base_url=config.base_url,
            api_key=config.api_key or "sk-no-key",
            timeout=config.timeout / 1000,
        )

    @property
    def name(self) -> ModelName:
        return ModelName.SEMANTIC

    @property
    def default_weight(self) -> float:
        return 0.4

    async def analyze(self, request: FilterRequest) -> DetectorOutput:
        start = time.monotonic()
        try:
            assessment = await self._call_llm(request)
            return DetectorOutput(
                model_name=self.name,
                score=assessment.risk_score,
                confidence=0.8,
                categories=[c.category.value for c in assessment.categories if c.category != RiskCategory.SAFE],
                reasoning=assessment.intent_reasoning,
                latency_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as e:
            return DetectorOutput(
                model_name=self.name,
                score=self._config.fallback_score,
                confidence=0.1,
                categories=[],
                reasoning=f"Semantic model unavailable: {e}",
                latency_ms=int((time.monotonic() - start) * 1000),
            )

    async def _call_llm(self, request: FilterRequest) -> RiskAssessment:
        user_prompt = build_user_prompt(
            [{"role": m.role, "content": m.content} for m in request.messages],
            request.system_prompt,
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        params = self._completion_params()
        last_error: Exception | None = None

        json_messages = [
            {
                "role": "system",
                "content": (
                    SYSTEM_PROMPT
                    + "\n\nReturn ONLY a valid JSON object matching this schema:\n"
                    + json.dumps(RiskAssessment.model_json_schema(), ensure_ascii=False)
                ),
            },
            {"role": "user", "content": user_prompt},
        ]

        for response_format in ({"type": "json_object"}, None):
            try:
                kwargs = {
                    "model": self._config.model,
                    "messages": json_messages,
                    **params,
                }
                if response_format is not None:
                    kwargs["response_format"] = response_format
                response = await self._client.chat.completions.create(**kwargs)
                content = response.choices[0].message.content or ""
                return RiskAssessment.model_validate_json(_extract_json(content))
            except Exception as e:
                last_error = e

        try:
            response = await self._client.chat.completions.parse(
                model=self._config.model,
                messages=messages,
                response_format=RiskAssessment,
                **params,
            )
            result = response.choices[0].message.parsed
            if result is not None:
                return result
            raise ValueError("Empty parsed LLM response")
        except Exception as e:
            last_error = e

        raise last_error or ValueError("Semantic model returned no valid response")

    def _completion_params(self) -> dict[str, object]:
        temperature = 1 if "gpt-5" in self._config.model.lower() else 0.1
        return {
            "temperature": temperature,
            "max_tokens": 1500,
        }


def _extract_json(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped
    match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
    if not match:
        raise ValueError("LLM response does not contain a JSON object")
    return match.group(0)
