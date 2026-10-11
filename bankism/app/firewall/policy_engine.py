"""Authoritative policy engine mapping risk metrics to final security verdicts."""

from dataclasses import dataclass

from bankism.app.firewall.risk_engine import RiskScoreResult
from bankism.app.schemas.requests import BankingOperation
from bankism.app.schemas.verdicts import RiskLevel, ThreatCategory, Verdict


@dataclass(frozen=True)
class PolicyDecision:
    """Authoritative output of security policy evaluation."""

    verdict: Verdict
    action_allowed: bool
    requires_review: bool
    reason: str


def evaluate_policy(
    risk: RiskScoreResult,
    operation: BankingOperation,
) -> PolicyDecision:
    """Enforces deterministic security boundaries independent of LLM behavior.

    Policy Invariants:
    1. HIGH or CRITICAL risk -> BLOCK (action_allowed=False).
    2. MEDIUM risk or AMBIGUOUS_REQUEST -> REVIEW (action_allowed=False, requires_review=True).
    3. CLASSIFIER_FAILURE on protected mutation (TRANSFER) -> BLOCK (fail-closed).
    4. LOW risk with zero critical signals -> APPROVE (action_allowed=True).
    """
    # 1. Fail-closed policy for classifier errors during mutations
    if risk.primary_category == ThreatCategory.CLASSIFIER_FAILURE:
        if operation == BankingOperation.TRANSFER:
            return PolicyDecision(
                verdict=Verdict.BLOCK,
                action_allowed=False,
                requires_review=False,
                reason=(
                    "Protected financial operation blocked due to classifier failure "
                    "(fail-closed policy)."
                ),
            )
        return PolicyDecision(
            verdict=Verdict.REVIEW,
            action_allowed=False,
            requires_review=True,
            reason="Classifier degraded; read-only request held for human review.",
        )

    # 2. Hard block for high and critical risks
    if risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        cat_name = risk.primary_category.value.replace("_", " ").lower()
        return PolicyDecision(
            verdict=Verdict.BLOCK,
            action_allowed=False,
            requires_review=False,
            reason=f"Request blocked due to high-severity threat detection: {cat_name}.",
        )

    # 3. Guarded review for medium risk and ambiguous requests
    if risk.level == RiskLevel.MEDIUM or risk.primary_category == ThreatCategory.AMBIGUOUS_REQUEST:
        if risk.primary_category == ThreatCategory.AMBIGUOUS_REQUEST:
            reason = (
                "Transfer held for human review: ambiguous recipient or transaction "
                "parameters require clarification."
            )
        else:
            reason = (
                "Request flagged with moderate risk indicators; requires verification "
                "before proceeding."
            )
        return PolicyDecision(
            verdict=Verdict.REVIEW,
            action_allowed=False,
            requires_review=True,
            reason=reason,
        )

    # 4. Standard approval for verified low-risk benign requests
    if risk.level == RiskLevel.LOW:
        return PolicyDecision(
            verdict=Verdict.APPROVE,
            action_allowed=True,
            requires_review=False,
            reason="Request inspected and approved with no adversarial indicators detected.",
        )

    # Default fallback: fail safe to BLOCK
    return PolicyDecision(
        verdict=Verdict.BLOCK,
        action_allowed=False,
        requires_review=False,
        reason="Security boundary evaluation completed with unresolved risk; failing closed.",
    )
