"""
Output Rail — filter LLM responses before user.
"""

from __future__ import annotations

import re

from app.core.types import FilterRequest, FilterResponse, Direction


_REDACT_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "[REDACTED_API_KEY]"),
    (r"gh[ps]_[a-zA-Z0-9]{36}", "[REDACTED_TOKEN]"),
    (r"AKIA[A-Z0-9]{16}", "[REDACTED_AWS_KEY]"),
    (r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", "Bearer [REDACTED]"),
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[REDACTED_EMAIL]"),
    (r"(?:\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}", "[REDACTED_PHONE]"),
    (
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        "[REDACTED_PRIVATE_KEY]",
    ),
    (r"(?:postgres|mysql|mongodb|redis)://[^\s'\"]+", "[REDACTED_CONNECTION_STRING]"),
]


def redact_pii(text: str) -> str:
    for pattern, replacement in _REDACT_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


async def output_rail(
    check: object,
    content: str,
    session_id: str | None = None,
) -> tuple[bool, FilterResponse | None, str]:
    result = await check(
        FilterRequest(
            messages=[{"role": "assistant", "content": content}],
            direction=Direction.OUTPUT,
            session_id=session_id,
        )
    )

    if result.verdict.value == "block":
        return False, result, ""

    if result.verdict.value == "review":
        return True, result, redact_pii(content)

    return True, result, content
