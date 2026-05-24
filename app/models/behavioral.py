"""
Behavioral Model — regex + heuristics + session history.
"""

from __future__ import annotations

import time

from app.models.base import BaseDetectorModel
from app.core.types import DetectorOutput, FilterRequest, ModelName
from app.rules.patterns import INJECTION_RULES, SECURITY_RULES, CONTENT_RULES, OUTPUT_RULES, match_rules


_session_blocks: dict[str, int] = {}


class BehavioralModel(BaseDetectorModel):
    @property
    def name(self) -> ModelName:
        return ModelName.BEHAVIORAL

    @property
    def default_weight(self) -> float:
        return 0.3

    async def analyze(self, request: FilterRequest) -> DetectorOutput:
        start = time.monotonic()
        text = _text_for_direction(request)

        if not text:
            return self._empty(start)

        rules = INJECTION_RULES + SECURITY_RULES + CONTENT_RULES
        if request.direction.value == "output":
            rules = OUTPUT_RULES

        matches = match_rules(rules, text)
        score = self._calculate_score(matches)
        score = self._apply_session_escalation(score, request.session_id)

        categories = list({m.category for m in matches})
        reasoning = (
            f"Matched {len(matches)} rules: {', '.join(m.rule_id for m in matches)}"
            if matches
            else "No behavioral patterns matched."
        )

        return DetectorOutput(
            model_name=self.name,
            score=min(score, 1.0),
            confidence=min(len(matches) * 0.2, 1.0) if matches else 0.3,
            categories=categories,
            reasoning=reasoning,
            latency_ms=int((time.monotonic() - start) * 1000),
        )

    def _calculate_score(self, matches: list) -> float:
        if not matches:
            return 0.0
        sorted_matches = sorted(matches, key=lambda m: m.severity, reverse=True)
        score = sorted_matches[0].severity
        for m in sorted_matches[1:]:
            score += m.severity * 0.4
        return min(score, 1.0)

    def _apply_session_escalation(self, score: float, session_id: str | None) -> float:
        if not session_id:
            return score
        blocks = _session_blocks.get(session_id, 0)
        if blocks >= 5:
            return min(score + 0.4, 1.0)
        if blocks >= 3:
            return min(score + 0.2, 1.0)
        return score

    def _empty(self, start: float) -> DetectorOutput:
        return DetectorOutput(
            model_name=self.name,
            score=0.0,
            confidence=0.3,
            categories=[],
            reasoning="No text to analyze.",
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def record_block(session_id: str | None) -> None:
    if not session_id:
        return
    _session_blocks[session_id] = _session_blocks.get(session_id, 0) + 1


def _text_for_direction(request: FilterRequest) -> str:
    if request.direction.value == "output":
        return " ".join(m.content for m in request.messages if m.role == "assistant")
    return " ".join(m.content for m in request.messages if m.role == "user")
