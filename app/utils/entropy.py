"""
Shannon entropy calculation.
"""

from __future__ import annotations

from collections import Counter


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * _log2(c / length) for c in freq.values())


def _log2(x: float) -> float:
    import math

    return math.log2(x) if x > 0 else 0.0
