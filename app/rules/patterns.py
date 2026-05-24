"""
Detection rules — injection, security, content policy, output patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern[str]
    category: str
    severity: float


def _rule(rule_id: str, pattern: str, category: str, severity: float) -> Rule:
    return Rule(id=rule_id, pattern=re.compile(pattern, re.IGNORECASE), category=category, severity=severity)


# --- Injection rules ---

INJECTION_RULES: list[Rule] = [
    _rule(
        "role_ignore_previous",
        r"ignore\s+(all\s+)?previous\s+(instructions|prompts|rules|directives)",
        "prompt_injection",
        0.8,
    ),
    _rule(
        "role_you_are_now",
        r"you\s+are\s+now\s+(DAN|an?\s+unrestricted|jailbroken|unfiltered|uncensored)",
        "jailbreak",
        0.9,
    ),
    _rule("role_system_prefix", r"^system\s*:", "prompt_injection", 0.7),
    _rule(
        "role_pretend",
        r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(unrestricted|unfiltered|uncensored|different|new)",
        "jailbreak",
        0.7,
    ),
    _rule("role_act_as", r"act\s+as\s+(if\s+you\s+(have\s+no|had\s+no)\s+|an?\s+unfiltered\s+)", "jailbreak", 0.7),
    _rule("role_new_instructions", r"new\s+instructions?\s*:", "prompt_injection", 0.7),
    _rule(
        "role_override",
        r"override\s+(your\s+|the\s+)?(safety|security|guidelines|rules|restrictions)",
        "prompt_injection",
        0.8,
    ),
    _rule("role_forget", r"forget\s+(everything\s+)?(you\s+)?(were\s+)?told", "prompt_injection", 0.7),
    _rule(
        "role_disregard",
        r"disregard\s+(all\s+)?(previous\s+|above\s+)?(instructions|rules|guidelines)",
        "prompt_injection",
        0.8,
    ),
    _rule(
        "role_bypass",
        r"bypass\s+(your\s+|the\s+)?(safety|security|content\s+)?(filter|guidelines|restrictions|rules)",
        "prompt_injection",
        0.8,
    ),
    _rule("inject_system_tag", r"<\s*system\s*>", "prompt_injection", 0.7),
    _rule("inject_instruction_tag", r"<\s*/?\s*instruction[s]?\s*>", "prompt_injection", 0.7),
    _rule("persona_dan", r"\bDAN\b.*\b(do anything now|jailbreak)\b", "jailbreak", 0.9),
    _rule(
        "context_above",
        r"above\s+(instructions|rules|guidelines)\s+(are\s+)?(no\s+longer|not|void|cancelled)",
        "prompt_injection",
        0.8,
    ),
    _rule("context_real", r"real\s+(instructions|rules)\s+(are|is)\s*:", "prompt_injection", 0.8),
    _rule(
        "context_updated",
        r"(your|the)\s+(instructions|rules|guidelines)\s+have\s+been\s+(updated|changed|modified)",
        "prompt_injection",
        0.8,
    ),
    _rule("context_admin", r"i\s+am\s+(your\s+)?(admin|developer|creator|owner)", "prompt_injection", 0.6),
    _rule(
        "ru_ignore_previous",
        r"игнорируй\s+(все\s+)?предыдущие\s+(инструкции|правила|указания)",
        "prompt_injection",
        0.8,
    ),
    _rule("ru_forget_rules", r"забудь\s+(все\s+)?(правила|инструкции|указания)(\s+выше)?", "prompt_injection", 0.7),
    _rule(
        "ru_bypass_filter",
        r"(обойди|обойти|отключи|отключить)\s+(фильтр|ограничения|правила|политику)",
        "prompt_injection",
        0.8,
    ),
    _rule(
        "ru_reveal_prompt",
        r"(покажи|выведи|раскрой)\s+(системн(ый|ую)\s+)?(промпт|инструкц(ию|ии)|правила)",
        "prompt_injection",
        0.8,
    ),
    _rule(
        "ru_no_limits",
        r"(без\s+ограничений|без\s+запретов|режим\s+разработчика|режим\s+без\s+ограничений)",
        "jailbreak",
        0.7,
    ),
]

# --- Security rules ---

SECURITY_RULES: list[Rule] = [
    _rule("path_etc", r"/etc/(passwd|shadow|hosts|hostname|ssh)", "data_exfiltration", 0.9),
    _rule("path_traversal", r"\.\.[/\\]\.\.[/\\]", "data_exfiltration", 0.7),
    _rule("path_dotenv", r"\.(env|env\.local|env\.production|env\.development)\b", "data_exfiltration", 0.8),
    _rule(
        "path_secrets",
        r"/(secrets?|credentials?|tokens?|keys?)/\w+\.(json|yml|yaml|conf|cfg)",
        "data_exfiltration",
        0.8,
    ),
    _rule("path_ssh", r"/\.ssh/(id_rsa|id_ed25519|authorized_keys|config)", "data_exfiltration", 0.9),
    _rule("path_aws", r"/\.aws/(credentials|config)", "data_exfiltration", 0.9),
    _rule("sql_drop", r"DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)", "data_exfiltration", 0.9),
    _rule("sql_union", r"UNION\s+(ALL\s+)?SELECT", "data_exfiltration", 0.7),
    _rule("sql_show", r"SHOW\s+(TABLES|DATABASES|SCHEMAS|COLUMNS)", "data_exfiltration", 0.6),
    _rule("cmd_rm_rf", r"rm\s+(-\w*r\w*f\w*|--recursive\s+--force)\s", "harmful_content", 0.9),
    _rule("cmd_curl_pipe", r"curl\s+.*\|\s*(sh|bash|python|perl)", "harmful_content", 0.8),
    _rule("cmd_wget_exec", r"wget\s+.*\|\s*(sh|bash|python|perl)", "harmful_content", 0.8),
    _rule("net_nc_reverse", r"nc\s+.*-e\s+(/bin/)?(bash|sh)", "data_exfiltration", 0.9),
    _rule(
        "config_read",
        r"(cat|type|read|head|tail|less|more)\s+.*\.(conf|config|ini|yml|yaml|json|toml)",
        "data_exfiltration",
        0.5,
    ),
    _rule("config_env", r"(printenv|env|export|set)\s", "data_exfiltration", 0.4),
]

# --- Content categories ---

CONTENT_RULES: list[Rule] = [
    _rule(
        "content_adult",
        r"\b(porn|porno|pornography|xxx|nsfw|naked|nude|nudes|sex|sexual|erotic|hentai|onlyfans|chaturbate)\b",
        "content_policy",
        0.7,
    ),
    _rule(
        "content_gambling",
        r"\b(casino|betting|букмекер|тотализатор|gambling|slot\s+machine|roulette|1xbet|melbet|fonbet|online\s+casino|sport\s+betting|crypto\s+casino)\b",
        "content_policy",
        0.6,
    ),
    _rule(
        "content_drugs",
        r"\b(buy\s+drugs|buy\s+cocaine|buy\s+heroin|купить\s+наркотик|наркотик\s+купить|alpha-pvp|darknet\s+market|how\s+to\s+make\s+drugs|drug\s+synthesis)\b",
        "content_policy",
        0.8,
    ),
    _rule(
        "content_violence",
        r"\b(how\s+to\s+kill|how\s+to\s+murder|как\s+убить|bomb\s+making|make\s+а\s+bomb|mass\s+shooting|school\s+shooting|terror\s+attack)\b",
        "content_policy",
        0.9,
    ),
    _rule(
        "content_child",
        r"\b(child\s+porn|cp\s+material|детское\s+порно|underage\s+nude|minor\s+sexual)\b",
        "content_policy",
        1.0,
    ),
    _rule(
        "content_illegal",
        r"\b(how\s+to\s+hack|как\s+взломать|credit\s+card\s+fraud|phishing\s+tutorial|counterfeit\s+money|money\s+laundering|illegal\s+weapon)\b",
        "content_policy",
        0.7,
    ),
    _rule(
        "content_fraud",
        r"\b(phishing\s+page|phishing\s+template|fake\s+passport|fake\s+id|fake\s+diploma|fake\s+receipt|spoof\s+email|pyramid\s+scheme|ponzi\s+scheme|crypto\s+scam|investment\s+scam|catfish\s+profile|фишинг|скам|мошенничество|пирамида|поддельный)\b",
        "fraud_scam",
        0.8,
    ),
]

# --- Output rules ---

OUTPUT_RULES: list[Rule] = [
    _rule("out_openai_key", r"sk-[a-zA-Z0-9]{20,}", "pii_leak", 0.9),
    _rule("out_github_token", r"gh[ps]_[a-zA-Z0-9]{36}", "pii_leak", 0.9),
    _rule("out_aws_key", r"AKIA[A-Z0-9]{16}", "pii_leak", 0.9),
    _rule("out_bearer", r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", "pii_leak", 0.8),
    _rule("out_jwt", r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "pii_leak", 0.8),
    _rule("out_email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "pii_leak", 0.5),
    _rule("out_phone_ru", r"(?:\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}", "pii_leak", 0.6),
    _rule("out_private_key", r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "pii_leak", 1.0),
    _rule("out_db_conn", r"(?:postgres|mysql|mongodb|redis)://[^\s'\"]+", "pii_leak", 0.9),
    _rule(
        "out_internal_ip",
        r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
        "pii_leak",
        0.6,
    ),
]


@dataclass
class RuleMatch:
    rule_id: str
    category: str
    severity: float
    matched_text: str


def match_rules(rules: list[Rule], text: str) -> list[RuleMatch]:
    matches = []
    for rule in rules:
        m = rule.pattern.search(text)
        if m:
            matches.append(
                RuleMatch(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    matched_text=m.group(),
                )
            )
    return matches
