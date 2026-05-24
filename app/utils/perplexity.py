"""
Perplexity scoring — detects adversarial suffixes (GCG, AutoDAN).

Two complementary methods (no LLM required):
1. Sliding-window compression ratio (language-agnostic, length-aware)
2. Rare character bigram ratio (detects unusual character sequences)

Normal text: low perplexity score. GCG adversarial suffixes: high score.
"""

from __future__ import annotations

import zlib

# Common English bigrams (~100, covers >60% of English text)
_EN_BIGRAMS = frozenset(
    {
        "th",
        "he",
        "in",
        "er",
        "an",
        "re",
        "on",
        "at",
        "en",
        "nd",
        "ti",
        "es",
        "or",
        "te",
        "of",
        "ed",
        "is",
        "it",
        "al",
        "ar",
        "st",
        "to",
        "nt",
        "ng",
        "se",
        "ha",
        "as",
        "ou",
        "io",
        "le",
        "ve",
        "co",
        "me",
        "de",
        "hi",
        "ri",
        "ro",
        "ic",
        "ne",
        "ea",
        "ra",
        "ce",
        "li",
        "ch",
        "ll",
        "be",
        "ma",
        "si",
        "om",
        "ur",
        "ab",
        "ad",
        "ai",
        "am",
        "ap",
        "el",
        "et",
        "ge",
        "il",
        "la",
        "no",
        "pe",
        "rs",
        "ss",
        "tt",
        "us",
        "wi",
        "wh",
        "wo",
        "yo",
        "so",
        "if",
        "we",
        "do",
        "su",
        "ag",
        "ca",
        "wa",
        "ec",
        "ac",
        "pr",
        "sh",
        "fi",
        "gh",
        "tu",
        "fu",
        "pl",
        "im",
        "bi",
        "pa",
        "ub",
        "ew",
        "ay",
        "fo",
        "lo",
        "ly",
        "ta",
        "ts",
        "ir",
        "oo",
    }
)

# Common Russian bigrams (~120)
_RU_BIGRAMS = frozenset(
    {
        "ст",
        "но",
        "то",
        "на",
        "ен",
        "ов",
        "ни",
        "ра",
        "во",
        "ко",
        "ть",
        "не",
        "по",
        "ка",
        "ал",
        "ли",
        "ер",
        "ре",
        "го",
        "ин",
        "ла",
        "ди",
        "от",
        "ан",
        "ос",
        "че",
        "тв",
        "ве",
        "ло",
        "ом",
        "ва",
        "ро",
        "пр",
        "та",
        "ри",
        "ор",
        "св",
        "мо",
        "да",
        "бо",
        "ск",
        "ми",
        "са",
        "ел",
        "об",
        "яз",
        "ше",
        "де",
        "ме",
        "ны",
        "те",
        "ле",
        "ви",
        "ав",
        "тр",
        "ль",
        "ат",
        "ча",
        "ие",
        "ек",
        "ся",
        "ит",
        "ир",
        "ис",
        "ое",
        "ет",
        "за",
        "ну",
        "со",
        "уд",
        "им",
        "ии",
        "хи",
        "ов",
        "ым",
        "ять",
        "ся",
        "чи",
        "ак",
        "ик",
        "ки",
        "лы",
        "ет",
        "ит",
        "ся",
        "ец",
        "ов",
        "ми",
        "ые",
        "ть",
        "ам",
        "ив",
        "ья",
        "сл",
        "му",
        "ях",
        "зы",
        "ри",
        "ре",
        "сь",
        "ых",
        "ую",
        "ог",
        "ся",
        "ие",
        "на",
        "ру",
        "чё",
        "жё",
        "би",
    }
)

_MIN_COMPRESS_LEN = 150
_MIN_PERPLEXITY_LEN = 120


def _detect_script(text: str) -> str:
    ru = sum(1 for c in text if "\u0400" <= c <= "\u04ff")
    en = sum(1 for c in text if c.isascii() and c.isalpha())
    return "ru" if ru > en and ru > 5 else "en"


def _window_compression(text: str, window: int = 200) -> float | None:
    """Best compression ratio across sliding windows. None if text too short."""
    if len(text) < _MIN_COMPRESS_LEN:
        return None

    best = 1.0
    step = max(window // 2, 50)
    for i in range(0, len(text) - window + 1, step):
        chunk = text[i : i + window]
        raw = chunk.encode("utf-8")
        cr = len(zlib.compress(raw, level=1)) / max(len(raw), 1)
        best = min(best, cr)
    return best


def rare_bigram_ratio(text: str) -> float:
    """Fraction of alphabetic bigrams absent from natural-language reference."""
    script = _detect_script(text)
    ref = _RU_BIGRAMS if script == "ru" else _EN_BIGRAMS

    text_lower = text.lower()
    bigrams = [
        text_lower[i : i + 2]
        for i in range(len(text_lower) - 1)
        if text_lower[i].isalpha() and text_lower[i + 1].isalpha()
    ]
    if not bigrams:
        return 0.0

    rare = sum(1 for bg in bigrams if bg not in ref)
    return rare / len(bigrams)


def perplexity_score(text: str) -> tuple[float, float, str]:
    """
    Combined perplexity assessment.

    Returns (score, raw_perplexity, details) where:
    - score: [0.0, 1.0] — 0 = normal, 1 = clearly adversarial
    - raw_perplexity: compression-ratio-based estimate
    - details: human-readable explanation
    """
    if len(text) < _MIN_PERPLEXITY_LEN:
        return 0.0, 1.0, "too short"

    cr = _window_compression(text)
    cr_score = 0.0
    raw_ppl = 1.0

    if cr is not None:
        raw_ppl = min(2 ** (cr * 8), 500.0)
        if cr > 0.85:
            cr_score = 0.9
        elif cr > 0.78:
            cr_score = 0.4

    rbr = rare_bigram_ratio(text)
    rbr_score = 0.0
    if rbr > 0.85:
        rbr_score = 0.9
    elif rbr > 0.72:
        rbr_score = 0.5
    elif rbr > 0.60:
        rbr_score = 0.1

    if cr is not None:
        combined = min(cr_score * 0.5 + rbr_score * 0.5, 1.0)
    else:
        combined = rbr_score

    parts: list[str] = []
    if cr_score > 0:
        parts.append(f"compression={cr:.2f}")
    if rbr_score > 0:
        parts.append(f"rare_bigrams={rbr:.0%}")

    details = "; ".join(parts) if parts else "normal"
    return combined, raw_ppl, details
