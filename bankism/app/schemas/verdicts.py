"""Pydantic schemas and enums for Bankism firewall verdicts and risk assessment."""

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Verdict(str, Enum):
    """Authoritative firewall verdict decisions."""

    APPROVE = "APPROVE"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class RiskLevel(str, Enum):
    """Discrete risk severity tiers."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    """Controlled taxonomy of adversarial and operational threats."""

    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    OBFUSCATION = "OBFUSCATION"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    UNAUTHORIZED_ACTION = "UNAUTHORIZED_ACTION"
    INVALID_INPUT = "INVALID_INPUT"
    AMBIGUOUS_REQUEST = "AMBIGUOUS_REQUEST"
    CLASSIFIER_FAILURE = "CLASSIFIER_FAILURE"


class FirewallVerdict(BaseModel):
    """Strict JSON verdict returned by the Bankism firewall pipeline."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(description="Unique request tracking identifier")
    verdict: Verdict = Field(description="Authoritative security decision (APPROVE, BLOCK, REVIEW)")
    risk_level: RiskLevel = Field(description="Calculated risk severity tier")
    risk_score: int = Field(ge=0, le=100, description="Deterministic risk score between 0 and 100")
    threat_category: ThreatCategory = Field(description="Primary classified threat category")
    reason: str = Field(description="Human-readable explanation of the security verdict")
    action_allowed: bool = Field(description="Indicates whether the requested action is permitted")
    requires_review: bool = Field(description="Indicates whether manual human review is required")

    # Cryptographic binding and diagnostic metadata
    execution_token: str | None = Field(
        default=None,
        description="Tamper-proof HMAC token issued ONLY for approved requests to permit execution",
    )
    threat_signals: list[str] = Field(
        default_factory=list,
        description="List of detected threat indicators or matched rule tags",
    )
    normalized_text: str | None = Field(
        default=None,
        description="Sanitized and de-obfuscated representation used for policy inspection",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of verdict generation",
    )
