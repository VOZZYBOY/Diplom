"""
Tool Rail — filter tool calls before execution.
Integrates Code Guard for sensitive tool analysis.
"""

from __future__ import annotations

import json

from app.core.config import SemanticModelConfig
from app.core.types import (
    FilterMessage,
    FilterRequest,
    FilterResponse,
    Verdict,
)
from app.guards.code_guard import analyze_code

_SENSITIVE_TOOLS = {"execute_python", "execute_js", "write_file", "read_file"}
_UNTRUSTED_ALLOWED_TOOLS = {
    "execute_python",
    "execute_js",
    "read_file",
    "write_file",
    "search_files",
    "search_text",
    "list_directory",
}
_UNTRUSTED_DENIED_TOOLS = {
    "send_dm",
    "manage_message",
    "schedule_task",
    "telegram_send",
    "telegram_delete",
    "shell",
    "run_command",
}


async def tool_rail(
    check: object,
    tool_name: str,
    tool_args: dict,
    messages: list,
    session_id: str | None = None,
    llm_config: SemanticModelConfig | None = None,
    trust_level: str = "trusted",
) -> tuple[bool, FilterResponse | None]:
    policy_result = _check_tool_policy(tool_name, trust_level)
    if policy_result is not None:
        return False, policy_result

    # Only analyze sensitive tools
    if tool_name not in _SENSITIVE_TOOLS:
        return True, None

    # Extract code from tool args
    code = tool_args.get("code") or tool_args.get("content") or json.dumps(tool_args)
    if not isinstance(code, str):
        code = str(code)

    # Code Guard: 3-layer analysis (static + behavioral + LLM)
    code_result = await analyze_code(
        code=code,
        tool_name=tool_name,
        tool_args=tool_args,
        llm_config=llm_config,
    )

    if code_result.verdict == Verdict.BLOCK:
        return False, code_result

    # Also run the general ensemble filter on the full conversation
    filter_req = FilterRequest(
        messages=[
            *messages,
            FilterMessage(
                role="assistant",
                content=f"Calling tool: {tool_name}({json.dumps(tool_args)})",
            ),
        ],
        direction="input",
        session_id=session_id,
    )

    result = await check(filter_req)

    # If both Code Guard and Ensemble flagged it → block
    if result.verdict.value == "block":
        return False, result

    # Code Guard returned REVIEW → return review result
    if code_result.verdict == Verdict.REVIEW:
        return True, code_result

    return True, result


def _check_tool_policy(tool_name: str, trust_level: str) -> FilterResponse | None:
    normalized = trust_level.lower()
    if normalized in {"trusted", "main", "admin"}:
        return None

    denied = tool_name in _UNTRUSTED_DENIED_TOOLS or tool_name not in _UNTRUSTED_ALLOWED_TOOLS
    if not denied:
        return None

    return FilterResponse(
        verdict=Verdict.BLOCK,
        risk_score=0.9,
        scores={"semantic": None, "behavioral": 0.9, "pattern": 0.0},
        weights={"semantic": 0.0, "behavioral": 1.0, "pattern": 0.0},
        categories=["tool_policy_violation"],
        reasoning=f"Tool '{tool_name}' is not allowed for trust level '{trust_level}'.",
        user_message="Tool call blocked by trust policy.",
        latency_ms=0,
    )
