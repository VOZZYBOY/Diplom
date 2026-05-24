"""
SGR prompt + schema for Code Guard — LLM-based code safety analysis.

SGR patterns applied:
- **Cascade**: code understanding → threat detection → obfuscation check → final score
- **Routing**: Literal threat types force explicit classification
- **Cycle**: List with min/max length forces structured threat enumeration
"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field


class CodeThreat(BaseModel):
    """Single code threat with severity and description."""

    threat_type: str = Field(
        description="Threat type: file_deletion, file_read_sensitive, "
        "network_exfiltration, network_download, command_injection, "
        "privilege_escalation, resource_exhaustion, data_destruction, "
        "credential_theft, code_execution, obfuscation, supply_chain, safe",
    )
    severity: float = Field(
        ge=0.0,
        le=1.0,
        description="Severity of this threat (0.0-1.0)",
    )
    description: str = Field(
        description="What specifically makes this code dangerous in this category",
    )


class CodeAssessment(BaseModel):
    """Structured output from Code Guard — enforced by SGR constrained decoding.

    Field ordering implements the Cascade pattern: the LLM must understand
    the code and identify threats before producing the final score.
    """

    # ── Phase 1: Code understanding ─────────────────────────────────────
    language: str = Field(
        description="Programming language: python, javascript, typescript, or unknown",
    )
    code_summary: str = Field(
        description="Brief summary of what this code actually DOES when executed",
    )

    # ── Phase 2: Threat detection (Cycle — 1 to 5 items) ───────────────
    threats: list[CodeThreat] = Field(
        min_length=1,
        max_length=5,
        description="List all detected threats (1-5 items). "
        "Use threat_type='safe' with severity=0 if no threats detected.",
    )

    # ── Phase 3: Obfuscation check ──────────────────────────────────────
    obfuscation_detected: bool = Field(
        description="Is the code obfuscated or trying to evade detection through "
        "string concatenation, encoding, dynamic dispatch, or misleading names?",
    )
    obfuscation_evidence: str = Field(
        description="Specific evidence of obfuscation, or 'none'",
    )

    # ── Final decision (Cascade — comes AFTER analysis) ─────────────────
    risk_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Overall risk score (0.0-1.0). "
        "0.0-0.15=safe, 0.15-0.3=low risk, 0.3-0.5=moderate, "
        "0.5-0.7=high, 0.7-0.85=dangerous, 0.85-1.0=critical",
    )
    blocked: bool = Field(
        description="Set to true when risk_score >= 0.7",
    )
    reasoning: str = Field(
        description="Detailed reasoning for the final decision based on evidence above",
    )
    safe_alternative: str = Field(
        description="Suggested safe alternative approach, or 'not applicable' if code is safe or no alternative exists",
    )


CODE_GUARD_SYSTEM_PROMPT = """<role>
You are a code security analyzer. You receive source code that a user asked an AI assistant to execute.
Your job is to determine whether this code is safe to run on a server.
You must be thorough — obfuscated malicious code must still be detected.
</role>

<task>
Analyze the provided code for security threats. The code will be executed on a server.
Walk through every phase. Do not skip any phase.
</task>

<analysis_pipeline>
<phase name="1_static">
Static analysis of code structure:
- What does this code actually DO when executed?
- Does it access the filesystem? Network? Environment variables? Other processes?
- Does it use dynamic code execution functions with computed arguments?
- Does it spawn subprocesses or shell commands?
- Are there obfuscated strings, encoded payloads, or indirect calls?
</phase>

<phase name="2_impact">
Assess potential damage:
- File system: delete/modify/encrypt files, read sensitive data
- Network: exfiltrate data, download malware, C2 communication
- Process: kill processes, fork bombs, resource exhaustion
- Privilege: escalate permissions, access credentials
- Supply chain: install packages, modify dependencies
</phase>

<phase name="3_obfuscation">
Detect evasion techniques:
- String concatenation to build dangerous commands piece by piece
- Using getattr with dynamic attribute names instead of direct calls
- Evaluating computed strings at runtime
- Base64/hex-encoded payloads decoded at runtime
- Lambda chains or nested calls to hide intent
- Variable names that mislead: "safe_helper" that deletes files
</phase>

<phase name="4_context">
Check the execution context:
- Is this normal development code (reading configs, file I/O within bounds)?
- Or does it exceed reasonable developer needs?
- Could this be legitimate but risky (e.g., a deployment script)?
- Does the tool_name matter? (execute_python vs execute_js vs write_file)
</phase>

<phase name="5_intent">
Determine the intent:
- Is the user trying to accomplish a legitimate task?
- Or is the code designed to cause harm, steal data, or compromise the system?
- Could this code be part of a prompt injection hidden in an uploaded file?
</phase>
</analysis_pipeline>

<threat_types>
<threat name="file_deletion">Deleting files or directories.</threat>
<threat name="file_read_sensitive">Reading sensitive files (passwords, .env, ssh keys, credentials).</threat>
<threat name="network_exfiltration">Sending data to external servers.</threat>
<threat name="network_download">Downloading and executing remote code.</threat>
<threat name="command_injection">Executing shell commands with user-controlled input.</threat>
<threat name="privilege_escalation">Escalating permissions beyond allowed scope.</threat>
<threat name="resource_exhaustion">Fork bombs, memory exhaustion, infinite loops with side effects.</threat>
<threat name="data_destruction">Overwriting files, formatting disks, truncating databases.</threat>
<threat name="credential_theft">Accessing environment variables, reading API keys, extracting tokens.</threat>
<threat name="code_execution">Dynamic code execution at runtime.</threat>
<threat name="obfuscation">Obfuscated or encoded payloads designed to evade detection.</threat>
<threat name="supply_chain">Installing packages, modifying dependencies.</threat>
<threat name="safe">Code is safe to execute — normal development task.</threat>
</threat_types>

<scoring_rules>
<rule>risk_score 0.0-0.15: Clearly safe code. Simple calculations, string processing, data transformation.</rule>
<rule>risk_score 0.15-0.3: Low risk. Reads local files but nothing sensitive. No network calls.</rule>
<rule>risk_score 0.3-0.5: Moderate risk. Uses subprocess but with fixed, safe commands. No user input in commands.</rule>
<rule>risk_score 0.5-0.7: High risk. Dynamic execution, file writes, or network calls.</rule>
<rule>risk_score 0.7-0.85: Dangerous. Clear malicious intent or significant damage potential.</rule>
<rule>risk_score 0.85-1.0: Critical. Obvious malware, data destruction, or system compromise.</rule>
<rule>Set blocked=true when risk_score >= 0.7</rule>
</scoring_rules>

<important>
- Analyze what the code ACTUALLY DOES when executed, not what it looks like.
- Obfuscated code should score HIGHER, not lower — evasion is itself suspicious.
- Normal file I/O (read a config, write a log) is safe. Deleting everything or reading secrets is not.
- Simple print or data processing -> risk_score 0.0, blocked false.
- Reading a JSON file for parsing -> risk_score 0.1, blocked false.
- Deleting files or running shell commands -> risk_score 0.9+, blocked true.
- Obfuscated destructive code -> risk_score 1.0, blocked true.
</important>"""


def build_code_prompt(
    code: str,
    tool_name: str,
    tool_args: dict | None = None,
    language: str | None = None,
) -> str:
    lang_hint = f"\n<detected_language>{language}</detected_language>" if language else ""
    args_section = ""
    if tool_args:
        args_section = f"\n<tool_arguments>\n{json.dumps(tool_args, indent=2)}\n</tool_arguments>"

    return f"""<tool_call tool="{tool_name}">{lang_hint}
<code_to_execute>
{code}
</code_to_execute>{args_section}
</tool_call_note>

<instruction>
Analyze the above code for security threats following all 5 phases.
This code is about to be EXECUTED on a server.
</instruction>"""
