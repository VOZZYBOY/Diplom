"""
Configuration via pydantic-settings — env vars + JSON file.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel


class ServerConfig(BaseModel):
    port: int = 3100
    host: str = "0.0.0.0"


class SemanticModelConfig(BaseModel):
    enabled: bool = True
    weight: float = 0.4
    model: str = "openai/openai/gpt-oss-120b"
    api_key: str = ""
    base_url: str = "https://litellm.mlops.itlabs.io"
    timeout: int = 10000
    fallback_score: float = 0.5


class BehavioralModelConfig(BaseModel):
    enabled: bool = True
    weight: float = 0.3
    session_tracking: bool = True
    max_session_blocks: int = 5


class PatternModelConfig(BaseModel):
    enabled: bool = True
    weight: float = 0.3
    entropy_threshold: float = 5.0
    max_repetition: int = 10
    special_char_ratio: float = 0.3
    detect_encodings: list[str] = ["base64", "hex", "unicode", "html_entity"]
    perplexity_enabled: bool = True
    perplexity_threshold: float = 0.5


class ThresholdsConfig(BaseModel):
    block: float = 0.75
    review: float = 0.50


class LoggingConfig(BaseModel):
    level: str = "info"
    log_blocked: bool = True
    log_allowed: bool = False
    log_review: bool = True


class FilterConfig(BaseModel):
    server: ServerConfig = ServerConfig()
    semantic: SemanticModelConfig = SemanticModelConfig()
    behavioral: BehavioralModelConfig = BehavioralModelConfig()
    pattern: PatternModelConfig = PatternModelConfig()
    thresholds: ThresholdsConfig = ThresholdsConfig()
    logging: LoggingConfig = LoggingConfig()


def load_config(path: str | None = None) -> FilterConfig:
    config_path = Path(path or "config/default.json")
    if config_path.exists():
        data = json.loads(config_path.read_text())
        # Env var substitution
        _substitute_env(data)
        return FilterConfig(**data)
    return FilterConfig()


def _substitute_env(obj: object) -> None:
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                env_name = v[2:-1]
                obj[k] = __import__("os").environ.get(env_name, "")
            elif isinstance(v, (dict, list)):
                _substitute_env(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                env_name = v[2:-1]
                obj[i] = __import__("os").environ.get(env_name, "")
            elif isinstance(v, (dict, list)):
                _substitute_env(v)
