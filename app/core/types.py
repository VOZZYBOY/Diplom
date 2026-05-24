"""
Core Pydantic types for the Multi-Model Ensemble Filter.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


# --- Enums ---


class Verdict(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class Direction(str, Enum):
    INPUT = "input"
    OUTPUT = "output"


class ModelName(str, Enum):
    SEMANTIC = "semantic"
    BEHAVIORAL = "behavioral"
    PATTERN = "pattern"


class IntentClassification(str, Enum):
    LEGITIMATE_QUESTION = "legitimate_question"
    INJECTION_ATTEMPT = "injection_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    CONTENT_POLICY_VIOLATION = "content_policy_violation"
    ROLE_MANIPULATION = "role_manipulation"
    ENCODING_ATTACK = "encoding_attack"
    FRAUD_SCAM = "fraud_scam"
    SAFE = "safe"


class RiskCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    CONTENT_POLICY = "content_policy"
    HARMFUL_CONTENT = "harmful_content"
    PII_LEAK = "pii_leak"
    FRAUD_SCAM = "fraud_scam"
    SAFE = "safe"


# --- Messages ---


class FilterMessage(BaseModel):
    role: str
    content: str


# --- Request / Response ---


class FilterRequest(BaseModel):
    messages: list[FilterMessage]
    direction: Direction
    system_prompt: str | None = None
    session_id: str | None = None
    models: list[ModelName] | None = None
    thresholds: ThresholdsOverride | None = None


class ThresholdsOverride(BaseModel):
    block: float | None = None
    review: float | None = None


class ModelScores(BaseModel):
    semantic: float | None = None
    behavioral: float | None = None
    pattern: float | None = None


class ModelWeights(BaseModel):
    semantic: float
    behavioral: float
    pattern: float


class FilterResponse(BaseModel):
    verdict: Verdict
    risk_score: float = Field(ge=0.0, le=1.0)
    scores: ModelScores
    weights: ModelWeights
    categories: list[str]
    reasoning: str
    user_message: str | None = None
    latency_ms: int
    sanitized_content: str | None = None
    redactions: list[str] = Field(default_factory=list)


# --- Detector output ---


class DetectorOutput(BaseModel):
    model_name: ModelName
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    categories: list[str]
    reasoning: str
    latency_ms: int


# --- Tool rail ---


class ToolFilterRequest(BaseModel):
    tool_name: str
    tool_args: dict[str, object]
    messages: list[FilterMessage]
    session_id: str | None = None
    trust_level: str = "trusted"


# --- Health ---


class ModelHealth(BaseModel):
    available: bool
    latency_ms: int


class HealthResponse(BaseModel):
    status: str
    models: dict[str, ModelHealth]
    version: str
