"""
Encoding detection and text structure analysis.
"""

from __future__ import annotations

import re


def detect_encodings(text: str) -> list[dict[str, object]]:
    patterns = [
        ("base64", r"[A-Za-z0-9+/]{20,}={0,2}", 0.3),
        ("hex_escape", r"(?:\\x[0-9a-f]{2}){5,}", 0.6),
        ("unicode_escape", r"(?:\\u[0-9a-f]{4}){3,}", 0.5),
        ("html_entity", r"(?:&#x?[0-9a-f]+;){3,}", 0.5),
        ("octal_escape", r"(?:\\[0-3]?[0-7]{1,2}){3,}", 0.5),
    ]
    matches = []
    for enc_type, pattern, suspicion in patterns:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            matches.append({"type": enc_type, "value": m.group(), "suspicion": suspicion})
    return matches


INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u00ad]")


def count_invisible_chars(text: str) -> int:
    return len(INVISIBLE_RE.findall(text))


def special_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    count = sum(1 for c in text if not c.isalnum() and c not in " \t\n\r")
    return count / len(text)


def digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if c.isdigit()) / len(text)


def non_ascii_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if ord(c) > 127) / len(text)


def max_repetition(text: str) -> int:
    if not text:
        return 0
    best = current = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            current += 1
            best = max(best, current)
        else:
            current = 1
    return best


def repeated_substrings(text: str, min_len: int = 5, max_results: int = 10) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for length in range(min_len, len(text) // 2 + 1):
        for i in range(len(text) - length + 1):
            sub = text[i : i + length]
            if sub in seen:
                continue
            seen.add(sub)
            if text.count(sub) >= 2:
                found.append(sub)
                if len(found) >= max_results:
                    return found
    return found
