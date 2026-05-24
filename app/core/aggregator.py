"""
Score aggregator — weighted voting with adaptive weights.
"""

from __future__ import annotations

from app.core.types import DetectorOutput, ModelName, Verdict


def aggregate_scores(
    outputs: list[DetectorOutput],
    weights: dict[ModelName, float],
    block_threshold: float,
    review_threshold: float,
) -> tuple[float, Verdict]:
    output_map = {o.model_name: o for o in outputs}

    risk_score = 0.0
    for name, weight in weights.items():
        output = output_map.get(name)
        if output:
            risk_score += weight * output.score

    max_detector_score = max((o.score for o in outputs), default=0.0)
    if max_detector_score >= review_threshold:
        risk_score = max(risk_score, max_detector_score)

    if risk_score >= block_threshold:
        verdict = Verdict.BLOCK
    elif risk_score >= review_threshold:
        verdict = Verdict.REVIEW
    else:
        verdict = Verdict.ALLOW

    return risk_score, verdict


def adjust_weights(
    base_weights: dict[ModelName, float],
    *,
    llm_available: bool,
    message_length: int,
    direction: str,
) -> dict[ModelName, float]:
    s = base_weights.get(ModelName.SEMANTIC, 0.4)
    b = base_weights.get(ModelName.BEHAVIORAL, 0.3)
    p = base_weights.get(ModelName.PATTERN, 0.3)

    if message_length < 20 and s > 0:
        s, b, p = 0.2, 0.4, 0.4

    if direction == "output":
        s, b, p = 0.3, 0.3, 0.4

    if not llm_available:
        if direction == "output":
            s, b, p = 0.0, 0.45, 0.55
        else:
            s, b, p = 0.0, 0.5, 0.5

    total = s + b + p
    if total == 0:
        return {ModelName.SEMANTIC: 0.0, ModelName.BEHAVIORAL: 0.5, ModelName.PATTERN: 0.5}

    return {
        ModelName.SEMANTIC: s / total,
        ModelName.BEHAVIORAL: b / total,
        ModelName.PATTERN: p / total,
    }
