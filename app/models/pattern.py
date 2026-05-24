"""
Pattern Model — entropy + encoding + structure analysis.
"""

from __future__ import annotations

import time

from app.models.base import BaseDetectorModel
from app.core.types import DetectorOutput, FilterRequest, ModelName
from app.utils.entropy import shannon_entropy
from app.utils.encoding import (
    count_invisible_chars,
    detect_encodings,
    digit_ratio,
    max_repetition,
    repeated_substrings,
    special_char_ratio,
)
from app.utils.perplexity import perplexity_score


class PatternModel(BaseDetectorModel):
    @property
    def name(self) -> ModelName:
        return ModelName.PATTERN

    @property
    def default_weight(self) -> float:
        return 0.3

    async def analyze(self, request: FilterRequest) -> DetectorOutput:
        start = time.monotonic()
        text = _text_for_direction(request)

        if not text:
            return self._empty(start)

        score = 0.0
        categories: list[str] = []
        reasons: list[str] = []

        entropy = shannon_entropy(text)
        if entropy > 5.5:
            score += 0.6
            categories.append("prompt_injection")
            reasons.append(f"High entropy ({entropy:.2f})")
        elif entropy > 4.5:
            score += 0.3
            categories.append("prompt_injection")
            reasons.append(f"Elevated entropy ({entropy:.2f})")

        # Perplexity scoring — detects GCG/AutoDAN adversarial suffixes
        ppl_score, raw_ppl, ppl_details = perplexity_score(text)
        if ppl_score >= 0.5:
            score += ppl_score
            categories.append("adversarial_suffix")
            reasons.append(f"High perplexity (ppl={raw_ppl:.0f}, {ppl_details})")
        elif ppl_score >= 0.25:
            score += ppl_score * 0.5
            categories.append("adversarial_suffix")
            reasons.append(f"Elevated perplexity (ppl={raw_ppl:.0f}, {ppl_details})")

        encodings = detect_encodings(text)
        for enc in encodings:
            score += enc["suspicion"]
        if encodings:
            categories.append("encoding_attack")
            reasons.append(f"Encodings: {', '.join(e['type'] for e in encodings)}")
        if len(encodings) > 2:
            score += 0.2

        rep = max_repetition(text)
        if rep > 10:
            score += 0.4
            categories.append("prompt_injection")
            reasons.append(f"Max repetition: {rep}")
        elif rep > 5:
            score += 0.2

        substrs = repeated_substrings(text)
        if len(substrs) > 3:
            score += 0.3
        elif len(substrs) > 1:
            score += 0.1

        scr = special_char_ratio(text)
        if scr > 0.3:
            score += 0.3
            categories.append("encoding_attack")
            reasons.append(f"Special char ratio: {scr:.0%}")
        elif scr > 0.2:
            score += 0.15

        if digit_ratio(text) > 0.4:
            score += 0.2

        invisible = count_invisible_chars(text)
        if invisible > 0:
            score += 0.5
            categories.append("prompt_injection")
            reasons.append(f"Invisible chars: {invisible}")

        if len(text) > 10000 and entropy > 4.0:
            score += 0.3

        reasoning = "; ".join(reasons) if reasons else "No structural anomalies detected."

        return DetectorOutput(
            model_name=self.name,
            score=min(score, 1.0),
            confidence=0.8 if score > 0.5 else 0.4,
            categories=list(set(categories)),
            reasoning=reasoning,
            latency_ms=int((time.monotonic() - start) * 1000),
        )

    def _empty(self, start: float) -> DetectorOutput:
        return DetectorOutput(
            model_name=self.name,
            score=0.0,
            confidence=0.3,
            categories=[],
            reasoning="No text to analyze.",
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _text_for_direction(request: FilterRequest) -> str:
    if request.direction.value == "output":
        return " ".join(m.content for m in request.messages if m.role == "assistant")
    return " ".join(m.content for m in request.messages if m.role == "user")
