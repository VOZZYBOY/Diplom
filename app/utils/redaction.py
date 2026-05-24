"""Sensitive data redaction for model outputs and tool results."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Redaction:
    kind: str
    count: int


_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "env_secret",
        re.compile(
            r"\b([A-Za-z0-9_]*(?:API[_-]?KEY|APIKEY|TOKEN|SECRET|PASSWORD|PASS|CREDENTIAL|AUTH)[A-Za-z0-9_]*)=([^\s\n]+)",
            re.IGNORECASE,
        ),
    ),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("github_token", re.compile(r"\bgh[ps]_[A-Za-z0-9]{36,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("telegram_token", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{35}\b")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._-]{20,}\b", re.IGNORECASE)),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    ),
    (
        "database_url",
        re.compile(r"\b(?:postgres|mysql|mongodb|redis)://[^\s'\"]+", re.IGNORECASE),
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN\s+(?:RSA\s+|OPENSSH\s+|EC\s+)?PRIVATE\s+KEY-----", re.IGNORECASE),
    ),
]


def redact_sensitive_text(text: str) -> tuple[str, list[Redaction]]:
    """Mask secrets while preserving enough context for audit logs."""
    redactions: list[Redaction] = []
    sanitized = text

    for kind, pattern in _SECRET_PATTERNS:
        sanitized, count = pattern.subn("[REDACTED]", sanitized)
        if count:
            redactions.append(Redaction(kind=kind, count=count))

    return sanitized, redactions
