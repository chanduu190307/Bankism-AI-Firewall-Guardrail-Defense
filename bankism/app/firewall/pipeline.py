"""Multi-stage inspection pipeline coordinator for Bankism AI Firewall."""

import logging

from bankism.app.core.security import create_execution_token
from bankism.app.firewall.normalizer import normalize_input
from bankism.app.firewall.policy_engine import evaluate_policy
from bankism.app.firewall.risk_engine import calculate_risk_score
from bankism.app.firewall.rule_engine import RuleMatch, evaluate_rules
from bankism.app.firewall.threat_classifier import ThreatClassifier, get_threat_classifier
from bankism.app.schemas.requests import FirewallAnalyzeRequest
from bankism.app.schemas.verdicts import FirewallVerdict, ThreatCategory, Verdict

logger = logging.getLogger("bankism.pipeline")


class FirewallPipeline:
    """Deterministic, defense-in-depth security inspection pipeline."""

    def __init__(self, classifier: ThreatClassifier | None = None) -> None:
        self.classifier = classifier or get_threat_classifier()

    async def inspect(self, request: FirewallAnalyzeRequest) -> FirewallVerdict:
        """Inspects incoming untrusted request and produces authoritative FirewallVerdict.

        Stages:
        1. Normalization & Obfuscation Extraction
        2. Deterministic Rule Matching (raw text, normalized text, decoded payloads, memo)
        3. Threat Classification (aggregates evidence / calls optional AI classifier)
        4. Mathematical Risk Scoring
        5. Authoritative Policy Evaluation
        6. Cryptographic Token Generation (ONLY for approved requests)
        """
        # Stage 1: Normalization & Obfuscation Decoding
        norm_result = normalize_input(request.text)

        # Stage 2: Rule Matching across surfaces
        rule_matches = evaluate_rules(norm_result.normalized_text, memo=request.memo)

        # Also evaluate decoded payloads if obfuscation was unpacked
        for decoded_p in norm_result.decoded_payloads:
            decoded_matches = evaluate_rules(decoded_p)
            for m in decoded_matches:
                if m.rule_id not in [rm.rule_id for rm in rule_matches]:
                    rule_matches.append(m)

        # Inspect monetary and recipient constraints on transfer operations
        from bankism.app.banking.authorization import SYNTHETIC_ACCOUNT_DIRECTORY
        from bankism.app.core.config import get_settings
        from bankism.app.firewall.rule_engine import (
            PATTERN_AMBIGUOUS_AMOUNT,
            PATTERN_AMBIGUOUS_RECIPIENT,
        )
        from bankism.app.schemas.requests import BankingOperation

        settings = get_settings()
        if request.operation == BankingOperation.TRANSFER:
            if request.amount is not None:
                if request.amount > settings.max_transaction_limit:
                    rule_matches.append(
                        RuleMatch(
                            rule_id="RULE_AMOUNT_EXCEEDED",
                            category=ThreatCategory.POLICY_VIOLATION,
                            severity_weight=75,
                            description=(
                                f"Amount exceeds maximum single limit of "
                                f"${settings.max_transaction_limit:.2f}."
                            ),
                            matched_snippet=f"${request.amount:.2f}",
                        )
                    )
                elif request.amount <= 0:
                    rule_matches.append(
                        RuleMatch(
                            rule_id="RULE_INVALID_AMOUNT",
                            category=ThreatCategory.INVALID_INPUT,
                            severity_weight=70,
                            description="Transfer amount must be positive.",
                            matched_snippet=str(request.amount),
                        )
                    )
            else:
                if PATTERN_AMBIGUOUS_AMOUNT.search(request.text):
                    rule_matches.append(
                        RuleMatch(
                            rule_id="RULE_AMBIGUOUS_AMOUNT",
                            category=ThreatCategory.AMBIGUOUS_REQUEST,
                            severity_weight=45,
                            description=(
                                "Transfer operation held for review: transfer amount is ambiguous "
                                "or unspecified."
                            ),
                            matched_snippet="None",
                        )
                    )
                else:
                    rule_matches.append(
                        RuleMatch(
                            rule_id="RULE_MISSING_AMOUNT",
                            category=ThreatCategory.INVALID_INPUT,
                            severity_weight=65,
                            description=(
                                "Transfer operation missing required transfer amount: amount must "
                                "be specified and positive."
                            ),
                            matched_snippet="None",
                        )
                    )

            if request.recipient_id:
                if request.recipient_id not in SYNTHETIC_ACCOUNT_DIRECTORY:
                    rule_matches.append(
                        RuleMatch(
                            rule_id="RULE_UNVERIFIED_RECIPIENT",
                            category=ThreatCategory.UNAUTHORIZED_ACTION,
                            severity_weight=75,
                            description=(
                                f"Recipient '{request.recipient_id}' is not in verified directory."
                            ),
                            matched_snippet=request.recipient_id,
                        )
                    )
                elif request.account_id and request.account_id == request.recipient_id:
                    rule_matches.append(
                        RuleMatch(
                            rule_id="RULE_SELF_TRANSFER",
                            category=ThreatCategory.POLICY_VIOLATION,
                            severity_weight=70,
                            description="Source and recipient accounts cannot be identical.",
                            matched_snippet=request.recipient_id,
                        )
                    )
            else:
                if PATTERN_AMBIGUOUS_RECIPIENT.search(request.text):
                    rule_matches.append(
                        RuleMatch(
                            rule_id="RULE_AMBIGUOUS_RECIPIENT",
                            category=ThreatCategory.AMBIGUOUS_REQUEST,
                            severity_weight=45,
                            description=(
                                "Transfer operation held for review: recipient is ambiguous or "
                                "missing ('someone who needs it')."
                            ),
                            matched_snippet="None",
                        )
                    )
                else:
                    rule_matches.append(
                        RuleMatch(
                            rule_id="RULE_MISSING_RECIPIENT",
                            category=ThreatCategory.INVALID_INPUT,
                            severity_weight=65,
                            description="Transfer operation missing required recipient account.",
                            matched_snippet="None",
                        )
                    )

            if request.account_id is None:
                rule_matches.append(
                    RuleMatch(
                        rule_id="RULE_MISSING_ACCOUNT",
                        category=ThreatCategory.INVALID_INPUT,
                        severity_weight=65,
                        description="Transfer operation missing required source account.",
                        matched_snippet="None",
                    )
                )

        # Stage 3: Threat Classification (evidence aggregation)
        classifier_result = await self.classifier.classify(
            text=request.text,
            normalized_text=norm_result.normalized_text,
            rule_matches=rule_matches,
            decoded_payloads=norm_result.decoded_payloads,
            metadata=request.client_metadata,
        )

        # Stage 4: Risk Scoring Calculation
        risk = calculate_risk_score(norm_result, rule_matches, classifier_result)

        # Stage 5: Policy Evaluation
        decision = evaluate_policy(risk, request.operation)

        # Stage 6: Cryptographic Execution Token Binding (issued ONLY if APPROVE)
        execution_token = None
        if decision.verdict == Verdict.APPROVE and request.account_id:
            # Enforce execution invariant: TRANSFER operations must have valid amount and recipient
            if request.operation == BankingOperation.TRANSFER and (
                request.amount is None or request.amount <= 0 or not request.recipient_id
            ):
                execution_token = None
            else:
                execution_token = create_execution_token(
                    request_id=request.request_id,
                    operation=request.operation.value,
                    account_id=request.account_id,
                    recipient_id=request.recipient_id,
                    amount=request.amount,
                    text=norm_result.normalized_text,
                )

        threat_signals = [m.rule_id for m in rule_matches]
        if norm_result.obfuscation_types:
            threat_signals.extend(norm_result.obfuscation_types)
        if classifier_result.signals:
            threat_signals.extend(s for s in classifier_result.signals if s not in threat_signals)

        return FirewallVerdict(
            request_id=request.request_id,
            verdict=decision.verdict,
            risk_level=risk.level,
            risk_score=risk.score,
            threat_category=risk.primary_category,
            reason=decision.reason,
            action_allowed=decision.action_allowed,
            requires_review=decision.requires_review,
            execution_token=execution_token,
            threat_signals=threat_signals,
            normalized_text=norm_result.normalized_text,
        )
