"""Unit tests for schemas, core config, logging redaction, and security tokens."""

import pytest
from pydantic import ValidationError

from bankism.app.core.errors import InvalidExecutionTokenError
from bankism.app.core.logging import redact_sensitive_dict, redact_sensitive_text
from bankism.app.core.security import create_execution_token, verify_execution_token
from bankism.app.schemas.requests import (
    BankingOperation,
    FirewallAnalyzeRequest,
)
from bankism.app.schemas.verdicts import (
    FirewallVerdict,
    RiskLevel,
    ThreatCategory,
    Verdict,
)


def test_firewall_verdict_valid() -> None:
    """Ensure FirewallVerdict accepts strictly conformant fields within bounds."""
    verdict = FirewallVerdict(
        request_id="req-12345",
        verdict=Verdict.APPROVE,
        risk_level=RiskLevel.LOW,
        risk_score=15,
        threat_category=ThreatCategory.NONE,
        reason="No threats detected in customer inquiry.",
        action_allowed=True,
        requires_review=False,
    )
    assert verdict.verdict == Verdict.APPROVE
    assert verdict.risk_score == 15
    assert verdict.action_allowed is True
    assert verdict.requires_review is False


def test_firewall_verdict_bounds() -> None:
    """Ensure risk_score strictly rejects values outside 0-100."""
    with pytest.raises(ValidationError):
        FirewallVerdict(
            request_id="req-bad-score",
            verdict=Verdict.BLOCK,
            risk_level=RiskLevel.HIGH,
            risk_score=105,  # Exceeds 100
            threat_category=ThreatCategory.PROMPT_INJECTION,
            reason="Invalid",
            action_allowed=False,
            requires_review=False,
        )

    with pytest.raises(ValidationError):
        FirewallVerdict(
            request_id="req-negative-score",
            verdict=Verdict.BLOCK,
            risk_level=RiskLevel.HIGH,
            risk_score=-5,  # Negative
            threat_category=ThreatCategory.PROMPT_INJECTION,
            reason="Invalid",
            action_allowed=False,
            requires_review=False,
        )


def test_firewall_analyze_request_validation() -> None:
    """Ensure request text rejects empty or whitespace-only strings."""
    with pytest.raises(ValidationError):
        FirewallAnalyzeRequest(text="   \n\t  ")

    req = FirewallAnalyzeRequest(text="What is my account balance?")
    assert req.text == "What is my account balance?"
    assert req.operation == BankingOperation.CUSTOMER_SUPPORT


def test_sensitive_text_redaction() -> None:
    """Ensure sensitive tokens, account numbers, and card numbers are masked."""
    raw = "Bearer eyJhbGciOiJIUzI1NiJ9.test and ACC-99281928 with card 4111 2222 3333 4444"
    redacted = redact_sensitive_text(raw)
    assert "Bearer [REDACTED_TOKEN]" in redacted
    assert "ACC-[REDACTED_ACC]" in redacted
    assert "[REDACTED_CARD]" in redacted
    assert "4111" not in redacted


def test_sensitive_dict_redaction() -> None:
    """Ensure dictionary values with sensitive keys are masked."""
    data = {
        "user": "Alice",
        "api_key": "secret-live-1234567890",
        "nested": {"token": "my-secret-jwt", "memo": "transfer for coffee"},
    }
    cleaned = redact_sensitive_dict(data)
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["nested"]["token"] == "[REDACTED]"
    assert cleaned["nested"]["memo"] == "transfer for coffee"


def test_execution_token_lifecycle() -> None:
    """Ensure cryptographic execution token lifecycle: create, verify, tamper, replay."""
    req_id = "req-test-99"
    op = "TRANSFER"
    acc = "ACC-1001"
    rec = "ACC-2002"
    amt = 150.00
    prompt_text = "Transfer $150 to Bob"

    # 1. Create valid token
    token = create_execution_token(
        request_id=req_id,
        operation=op,
        account_id=acc,
        recipient_id=rec,
        amount=amt,
        text=prompt_text,
    )
    assert isinstance(token, str)
    assert "." in token

    # 2. Tampered token fails
    parts = token.split(".", 1)
    tampered_token = f"{parts[0]}tampered.{parts[1]}"
    with pytest.raises(InvalidExecutionTokenError, match="cryptographic signature is invalid"):
        verify_execution_token(
            token=tampered_token,
            expected_operation=op,
            expected_account_id=acc,
            expected_recipient_id=rec,
            expected_amount=amt,
            expected_text=prompt_text,
        )

    # 3. Context mismatch fails: altered recipient
    with pytest.raises(InvalidExecutionTokenError, match="recipient binding mismatch"):
        verify_execution_token(
            token=token,
            expected_operation=op,
            expected_account_id=acc,
            expected_recipient_id="ACC-HACKER",
            expected_amount=amt,
            expected_text=prompt_text,
        )

    # 4. Context mismatch fails: altered amount
    with pytest.raises(InvalidExecutionTokenError, match="transaction amount mismatch"):
        verify_execution_token(
            token=token,
            expected_operation=op,
            expected_account_id=acc,
            expected_recipient_id=rec,
            expected_amount=999.00,  # Elevated amount!
            expected_text=prompt_text,
        )

    # 5. Legitimate verification succeeds
    verified = verify_execution_token(
        token=token,
        expected_operation=op,
        expected_account_id=acc,
        expected_recipient_id=rec,
        expected_amount=amt,
        expected_text=prompt_text,
    )
    assert verified["req_id"] == req_id
    assert verified["op"] == op

    # 6. Replay attempt fails (single-use token consumed)
    with pytest.raises(InvalidExecutionTokenError, match="already been consumed"):
        verify_execution_token(
            token=token,
            expected_operation=op,
            expected_account_id=acc,
            expected_recipient_id=rec,
            expected_amount=amt,
            expected_text=prompt_text,
        )
