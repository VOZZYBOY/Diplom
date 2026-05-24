"""
Input Rail — filter user messages before LLM.
"""

from __future__ import annotations

from app.core.types import FilterRequest, FilterResponse


async def input_rail(
    check: object,
    messages: list,
    session_id: str | None = None,
    system_prompt: str | None = None,
) -> tuple[bool, FilterResponse | None]:
    from app.core.types import Direction

    result = await check(
        FilterRequest(
            messages=messages,
            direction=Direction.INPUT,
            session_id=session_id,
            system_prompt=system_prompt,
        )
    )
    return result.verdict.value != "block", result
