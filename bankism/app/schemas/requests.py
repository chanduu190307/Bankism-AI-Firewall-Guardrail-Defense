"""Pydantic schemas for firewall analysis, banking requests, and execution responses."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class BankingOperation(str, Enum):
    """Allowed banking actions inspected by the firewall."""

    BALANCE_INQUIRY = "BALANCE_INQUIRY"
    TRANSFER = "TRANSFER"
    STATEMENT_REQUEST = "STATEMENT_REQUEST"
    CUSTOMER_SUPPORT = "CUSTOMER_SUPPORT"


class TransactionStatus(str, Enum):
    """Status outcomes for banking transaction execution."""

    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"


class FirewallAnalyzeRequest(BaseModel):
    """Request payload sent to POST /api/v1/firewall/analyze."""

    model_config = ConfigDict(extra="ignore")

    request_id: str = Field(
        default_factory=lambda: f"req-{uuid.uuid4().hex[:12]}",
        description="Unique caller-supplied or generated request ID",
    )
    text: str = Field(
        min_length=1,
        max_length=4000,
        description="Untrusted natural language text, prompt, or instruction",
    )
    operation: BankingOperation = Field(
        default=BankingOperation.CUSTOMER_SUPPORT,
        description="Target banking operation",
    )
    account_id: str | None = Field(
        default=None,
        max_length=32,
        description="Source bank account identifier",
    )
    recipient_id: str | None = Field(
        default=None,
        max_length=32,
        description="Recipient bank account identifier (for transfers)",
    )
    amount: float | None = Field(
        default=None,
        ge=0,
        le=1_000_000,
        description="Simulated monetary amount for financial actions",
    )
    memo: str | None = Field(
        default=None,
        max_length=500,
        description="Payment memo or transfer reference text",
    )
    client_metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional telemetry, IP, or user-agent context",
    )

    @field_validator("text")
    @classmethod
    def validate_text_not_pure_whitespace(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Request text cannot be empty or solely whitespace.")
        return v


class BankingExecuteRequest(BaseModel):
    """Request payload sent to POST /api/v1/banking/execute."""

    model_config = ConfigDict(extra="ignore")

    request_id: str = Field(
        default_factory=lambda: f"req-{uuid.uuid4().hex[:12]}",
        description="Unique request ID",
    )
    operation: BankingOperation = Field(
        description="Banking operation to execute",
    )
    account_id: str = Field(
        min_length=3,
        max_length=32,
        description="Source synthetic account identifier",
    )
    recipient_id: str | None = Field(
        default=None,
        max_length=32,
        description="Target synthetic account identifier for transfers",
    )
    amount: float | None = Field(
        default=None,
        ge=0,
        description="Amount to transfer",
    )
    memo: str | None = Field(
        default=None,
        max_length=500,
        description="Payment memo",
    )
    raw_prompt: str | None = Field(
        default=None,
        max_length=4000,
        description="Original conversational prompt that triggered this execution",
    )
    execution_token: str | None = Field(
        default=None,
        description="Cryptographic HMAC token issued by the firewall analyze endpoint",
    )
    idempotency_key: str | None = Field(
        default=None,
        max_length=64,
        description="Unique client idempotency token preventing duplicate transfers",
    )
    client_role: str | None = Field(
        default=None,
        description="Untrusted client-supplied role (tested for authorization bypass rejection)",
    )


class BankingExecutionResponse(BaseModel):
    """Response returned upon mock banking execution."""

    model_config = ConfigDict(extra="forbid")

    transaction_id: str = Field(description="Unique simulated transaction ID")
    status: TransactionStatus = Field(description="Final execution outcome")
    operation: BankingOperation = Field(description="Executed operation")
    source_account: str = Field(description="Debited or queried account")
    recipient_account: str | None = Field(default=None, description="Credited account")
    amount: float | None = Field(default=None, description="Executed transaction amount")
    currency: str = Field(default="USD", description="Currency symbol")
    previous_balance: float | None = Field(default=None, description="Starting balance")
    new_balance: float | None = Field(default=None, description="Final balance after execution")
    executed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Timestamp of execution",
    )
    message: str = Field(description="User-friendly result message")


class HealthResponse(BaseModel):
    """Sanitized application health response."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="HEALTHY")
    version: str = Field(default="1.0.0")
    service: str = Field(default="Bankism AI Firewall & Guardrail Defense")
    classifier_status: str = Field(default="ONLINE (HEURISTIC)")
    uptime_seconds: float = Field(ge=0)


class AuditLogRecord(BaseModel):
    """Structured audit trail record."""

    model_config = ConfigDict(extra="forbid")

    audit_id: str
    timestamp: str
    request_id: str
    operation: str
    account_id: str | None
    recipient_id: str | None
    amount: float | None
    risk_score: int
    risk_level: str
    verdict: str
    threat_category: str
    threat_signals: list[str]
    executed: bool
    reason: str
