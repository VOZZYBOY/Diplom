"""
Code Guard — 3-layer code analysis before execution.

Layer 1: Static heuristic analysis (instant, no LLM)
Layer 2: Behavioral pattern matching (instant, no LLM)
Layer 3: LLM semantic analysis via SGR (200-500ms)
"""

from __future__ import annotations

import logging
import re
import time

from openai import AsyncOpenAI

from app.core.config import SemanticModelConfig
from app.core.types import FilterResponse, ModelScores, ModelWeights, Verdict
from app.schemas.code_guard import (
    CODE_GUARD_SYSTEM_PROMPT,
    CodeAssessment,
    build_code_prompt,
)

logger = logging.getLogger("llm-filter")

# ── Layer 1: Static heuristic analysis ──────────────────────────────────

_DANGEROUS_PATTERNS: list[tuple[str, float, str]] = [
    (r"rm\s+-rf\s+/", 0.95, "recursive_delete_root"),
    (r"rm\s+-rf", 0.85, "recursive_delete"),
    (r"chmod\s+777", 0.7, "permission_widen"),
    (r"mkfs\.", 0.9, "format_disk"),
    (r"curl\s+.*\|\s*(?:sh|bash)", 0.95, "download_and_execute"),
    (r"wget\s+.*\|\s*(?:sh|bash)", 0.95, "download_and_execute"),
    (r"pip\s+install\s+--(?:no-verify|no-deps)", 0.6, "unsafe_install"),
    (r":\(\)\{.*;\}\s*;", 0.9, "fork_bomb"),
    (r"import\s+socket\b", 0.4, "network_socket"),
    (r"requests\.(?:post|put|patch)\s*\(", 0.5, "network_send"),
    (r"urllib\.request\.urlopen", 0.4, "network_request"),
    (r"fetch\s*\(", 0.3, "network_fetch"),
    (r"XMLHttpRequest", 0.3, "network_request"),
    (r"os\.environ", 0.4, "env_access"),
    (r"process\.env", 0.4, "env_access"),
    (r"/etc/passwd", 0.85, "read_sensitive_file"),
    (r"/etc/shadow", 0.9, "read_sensitive_file"),
    (r"/proc/self/environ", 0.9, "read_process_environment"),
    (r"/proc/\d+/environ", 0.9, "read_process_environment"),
    (r"/run/secrets", 0.95, "read_docker_secrets"),
    (r"/var/run/secrets", 0.95, "read_docker_secrets"),
    (r"\.ssh/", 0.7, "ssh_access"),
    (r"\.env\b", 0.5, "dotenv_access"),
    (r"os\.getenv", 0.5, "env_access"),
    (r"from\s+os\s+import\s+environ", 0.7, "env_access"),
    (r"load_dotenv|dotenv", 0.7, "dotenv_access"),
    (r"getpass\b", 0.3, "password_prompt"),
    (r"keylog", 0.9, "keylogger"),
    (r"ransomware|ransom", 0.95, "ransomware"),
    (r"reverse.?shell", 0.95, "reverse_shell"),
    (r"bind.?shell", 0.9, "bind_shell"),
    (r"/dev/tcp/|/dev/udp/", 0.95, "reverse_shell"),
    (r"\bnc\s+.*-(?:e|c)\s", 0.95, "reverse_shell"),
    (r"\bsocat\b.*exec:", 0.95, "reverse_shell"),
    (r"\b(?:nmap|masscan|zmap)\b", 0.8, "network_scan"),
    (r"\b(?:xmrig|cpuminer|minerd)\b", 0.95, "crypto_mining"),
    (r"\b(?:sqlmap|msfvenom|msfconsole|metasploit)\b", 0.9, "attack_tool"),
    (r"\b(?:yes\s*$|yes\s*\||sleep\s+[0-9]{4,})", 0.8, "dos_resource_abuse"),
    (r"/dev/(?:zero|urandom).*dd", 0.9, "dos_resource_abuse"),
    (r"head\s+-c\s*[0-9]{10,}", 0.8, "dos_resource_abuse"),
    (r"dd\s+.*count=[0-9]{7,}", 0.8, "dos_resource_abuse"),
    (r"(?:fallocate|truncate)\s+.*[0-9]+[GT]", 0.85, "dos_resource_abuse"),
    (r"(?:curl|wget).*\.sh\s*\|\s*(?:sh|bash)", 0.95, "download_and_execute"),
]

_OBFUSCATION_INDICATORS: list[tuple[str, float, str]] = [
    (r"getattr\s*\(\s*\w+\s*,\s*['\"]", 0.3, "getattr_dynamic"),
    (r"__import__\s*\(", 0.4, "dynamic_import"),
    (r"\w+\s*\+\s*['\"]", 0.15, "string_concat"),
    (r"(?:base64|b64decode|b64encode)", 0.3, "base64_usage"),
    (r"(?:b64decode|atob).*?(?:exec|eval)", 0.8, "decode_and_execute"),
    (r"aW1wb3J0IG9z|b3MuZW52aXJvbg|L3Byb2Mvc2VsZi9lbnZpcm9u|L3J1bi9zZWNyZXRz", 0.8, "encoded_secret_access"),
    (r"\b[A-Za-z0-9+/]{80,}={0,2}\b", 0.4, "long_base64_payload"),
    (r"decode\s*\(\s*['\"]hex['\"]", 0.25, "hex_decode"),
    (r"chr\s*\(\s*\d+\s*\)", 0.2, "chr_encoding"),
    (r"bytes\s*\(\s*\[.*\]\s*\)\.decode", 0.4, "bytes_decode"),
    (r"\[::-1\]", 0.3, "string_reverse"),
    (r"\\x[0-9a-f]{2}", 0.15, "hex_escape"),
    (r"\\u[0-9a-f]{4}", 0.1, "unicode_escape"),
    (r"compile\s*\(", 0.35, "compile_usage"),
    (r"__builtins__|__globals__|__code__", 0.6, "python_internals"),
    (r"importlib\.import_module", 0.5, "dynamic_import"),
    (r"Function\s*\(", 0.4, "js_dynamic_function"),
]


def _static_analysis(code: str) -> tuple[float, list[str]]:
    """Layer 1: instant heuristic scoring."""
    threats: list[str] = []
    max_score = 0.0

    for pattern, severity, name in _DANGEROUS_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            threats.append(name)
            max_score = max(max_score, severity)

    for pattern, penalty, name in _OBFUSCATION_INDICATORS:
        if re.search(pattern, code, re.IGNORECASE):
            threats.append(f"obfuscation:{name}")
            max_score = min(max_score + penalty, 1.0)

    return max_score, threats


# ── Layer 2: Behavioral pattern matching ─────────────────────────────────

_BEHAVIORAL_CODE_RULES: list[tuple[str, float, str]] = [
    (r"(?:exec|eval)\s*\(", 0.7, "dynamic_execution"),
    (r"subprocess\.\w+\s*\(\s*shell\s*=\s*True", 0.8, "shell_true"),
    (r"os\.system\s*\(", 0.8, "os_system"),
    (r"os\.popen\s*\(", 0.7, "os_popen"),
    (r"open\s*\(\s*['\"].*(?:/etc/|\.ssh|\.env|\.gnupg)", 0.7, "sensitive_file_open"),
    (r"open\s*\(\s*['\"].*(?:/run/secrets|/proc/self/environ)", 0.9, "sensitive_file_open"),
    (r"shutil\.rmtree\s*\(", 0.85, "rmtree"),
    (r"pickle\.loads?\s*\(", 0.5, "unsafe_deserialize"),
    (r"sendmail|smtplib", 0.3, "email_send"),
    (r"tempfile\.mktemp\s*\(", 0.3, "unsafe_tempfile"),
    (r"Pickle\.loads?\s*\(", 0.5, "unsafe_deserialize"),
    (r"yaml\.load\s*\([^)]*(?!Loader)", 0.4, "unsafe_yaml"),
]


def _behavioral_analysis(code: str) -> tuple[float, list[str]]:
    """Layer 2: behavioral pattern scoring."""
    threats: list[str] = []
    max_score = 0.0

    for pattern, severity, name in _BEHAVIORAL_CODE_RULES:
        if re.search(pattern, code, re.IGNORECASE):
            threats.append(name)
            max_score = max(max_score, severity)

    return max_score, threats


# ── Layer 3: LLM semantic analysis ──────────────────────────────────────


async def _llm_analysis(
    code: str,
    tool_name: str,
    tool_args: dict | None,
    config: SemanticModelConfig,
) -> tuple[float, list[dict], str]:
    """Layer 3: LLM-based code analysis via SGR."""
    lang = "python" if tool_name == "execute_python" else "javascript"
    user_prompt = build_code_prompt(code, tool_name, tool_args, language=lang)

    try:
        client = AsyncOpenAI(
            base_url=config.base_url,
            api_key=config.api_key or "sk-no-key",
            timeout=config.timeout / 1000,
        )

        response = await client.chat.completions.parse(
            model=config.model,
            messages=[
                {"role": "system", "content": CODE_GUARD_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format=CodeAssessment,
            temperature=0.05,
            max_tokens=1500,
        )

        assessment = response.choices[0].message.parsed
        if assessment is None:
            raise ValueError("Empty LLM response")

        threats = [t.model_dump() for t in assessment.threats]
        return assessment.risk_score, threats, assessment.reasoning

    except Exception as e:
        logger.warning("Code Guard LLM failed: %s", e)
        return 0.5, [], f"LLM analysis unavailable: {e}"


# ── Code Guard: orchestrator ─────────────────────────────────────────────


async def analyze_code(
    code: str,
    tool_name: str,
    tool_args: dict | None = None,
    llm_config: SemanticModelConfig | None = None,
) -> FilterResponse:
    """
    Run 3-layer code analysis and return a FilterResponse.

    Decision logic:
    - Layer 1 (static) score >= 0.9 → instant BLOCK, skip LLM
    - Layer 2 (behavioral) score >= 0.8 → instant BLOCK, skip LLM
    - Otherwise run Layer 3 (LLM) and take MAX of all three
    """
    start = time.monotonic()

    # Layer 1: static
    static_score, static_threats = _static_analysis(code)
    logger.info("CodeGuard L1 static: score=%.2f threats=%s", static_score, static_threats)

    # Layer 2: behavioral
    behav_score, behav_threats = _behavioral_analysis(code)
    logger.info("CodeGuard L2 behavioral: score=%.2f threats=%s", behav_score, behav_threats)

    # Early exit on obvious threats
    early_block = static_score >= 0.9 or behav_score >= 0.8
    all_threats = static_threats + behav_threats
    heuristic_score = max(static_score, behav_score)

    if early_block:
        latency = int((time.monotonic() - start) * 1000)
        logger.info("CodeGuard EARLY BLOCK: heuristic=%.2f (no LLM needed)", heuristic_score)
        return FilterResponse(
            verdict=Verdict.BLOCK,
            risk_score=heuristic_score,
            scores=ModelScores(semantic=None, behavioral=behav_score, pattern=static_score),
            weights=ModelWeights(semantic=0.4, behavioral=0.3, pattern=0.3),
            categories=all_threats,
            reasoning=f"Heuristic block: {', '.join(all_threats)}",
            user_message="Выполнение кода заблокировано: обнаружены опасные операции.",
            latency_ms=latency,
        )

    # Layer 3: LLM analysis
    llm_score = 0.0
    llm_threats: list[dict] = []
    llm_reasoning = ""

    if llm_config:
        llm_score, llm_threats, llm_reasoning = await _llm_analysis(code, tool_name, tool_args, llm_config)
        logger.info(
            "CodeGuard L3 LLM: score=%.2f threats=%s",
            llm_score,
            [t.get("threat_type") for t in llm_threats],
        )

    final_score = max(static_score, behav_score, llm_score)
    latency = int((time.monotonic() - start) * 1000)

    categories = list(set(all_threats + [t.get("threat_type", "") for t in llm_threats if t.get("threat_type")]))

    if final_score >= 0.75:
        verdict = Verdict.BLOCK
        user_msg = "Выполнение кода заблокировано: обнаружены потенциально опасные операции."
    elif final_score >= 0.5:
        verdict = Verdict.REVIEW
        user_msg = None
    else:
        verdict = Verdict.ALLOW
        user_msg = None

    reasoning_parts = []
    if static_threats:
        reasoning_parts.append(f"Static: {', '.join(static_threats)}")
    if behav_threats:
        reasoning_parts.append(f"Behavioral: {', '.join(behav_threats)}")
    if llm_reasoning:
        reasoning_parts.append(f"LLM: {llm_reasoning}")
    reasoning = " | ".join(reasoning_parts) or "No threats detected"

    logger.info(
        "CodeGuard RESULT: verdict=%s score=%.2f (S=%.2f B=%.2f L=%.2f) latency=%dms",
        verdict.value,
        final_score,
        static_score,
        behav_score,
        llm_score,
        latency,
    )

    return FilterResponse(
        verdict=verdict,
        risk_score=final_score,
        scores=ModelScores(semantic=llm_score or None, behavioral=behav_score, pattern=static_score),
        weights=ModelWeights(semantic=0.4, behavioral=0.3, pattern=0.3),
        categories=categories,
        reasoning=reasoning,
        user_message=user_msg,
        latency_ms=latency,
    )
