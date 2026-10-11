"""Mathematical risk engine with indicator weighting and deterministic threshold bounds."""

from dataclasses import dataclass

from bankism.app.core.config import get_settings
from bankism.app.firewall.normalizer import NormalizationResult
from bankism.app.firewall.rule_engine import RuleMatch
from bankism.app.firewall.threat_classifier import ClassifierResult
from bankism.app.schemas.verdicts import RiskLevel, ThreatCategory


@dataclass(frozen=True)
class RiskScoreResult:
    """Documented breakdown of computed risk metrics."""

    score: int  # 0 to 100
    level: RiskLevel
    breakdown: dict[str, int]
    primary_category: ThreatCategory


def calculate_risk_score(
    norm_result: NormalizationResult,
    rule_matches: list[RuleMatch],
    classifier_result: ClassifierResult,
) -> RiskScoreResult:
    """Calculates deterministic risk score between 0 and 100.

    Mathematical Formulation:
    -------------------------
    1. Base: 0
    2. Rule Category Max: Prevents duplicate inflation by taking max weight per threat category.
    3. Obfuscation Bonus: Penalizes hidden unicode and decoded suspicious payloads.
    4. Benign Mitigation: Offsets false positives for educational security discussions.
    5. Classifier Failure: Fails closed to 75 (HIGH) if security classifier degraded.
    6. Bounds: Clamped strictly to [0, 100].
    """
    settings = get_settings()
    breakdown: dict[str, int] = {}
    total_score = 0

    # 1. Evaluate Rule matches by category to prevent duplicate counting
    category_weights: dict[ThreatCategory, int] = {}
    for match in rule_matches:
        category_weights[match.category] = max(
            category_weights.get(match.category, 0), match.severity_weight
        )

    for cat, weight in category_weights.items():
        breakdown[f"rule_category_{cat.value}"] = weight
        total_score += weight

    # 2. Obfuscation contribution
    if norm_result.obfuscation_detected:
        obf_score = 0
        if norm_result.stripped_zero_width_count > 0:
            obf_score += 35
        if norm_result.decoded_payloads:
            obf_score += 25
        breakdown["obfuscation_penalty"] = obf_score
        total_score += obf_score

    # 3. Classifier specific signals
    if (
        classifier_result.is_degraded
        or classifier_result.predicted_category == ThreatCategory.CLASSIFIER_FAILURE
    ):
        fail_closed_penalty = 75
        breakdown["classifier_failure_penalty"] = fail_closed_penalty
        total_score = max(total_score, fail_closed_penalty)
    elif (
        classifier_result.predicted_category == ThreatCategory.AMBIGUOUS_REQUEST
        and ThreatCategory.AMBIGUOUS_REQUEST not in category_weights
    ):
        ambiguous_penalty = 30
        breakdown["ambiguous_formatting_penalty"] = ambiguous_penalty
        total_score += ambiguous_penalty

    # 4. Context mitigation (educational/benign security inquiry)
    if "BENIGN_SECURITY_DISCUSSION_CONTEXT" in classifier_result.signals:
        mitigation = -total_score + 10
        breakdown["benign_context_mitigation"] = mitigation
        total_score = 10

    # 5. Strict mathematical clamping to [0, 100]
    final_score = max(0, min(100, int(round(total_score))))

    # 6. Map to discrete risk tiers
    if final_score <= settings.risk_low_max:
        level = RiskLevel.LOW
    elif final_score <= settings.risk_medium_max:
        level = RiskLevel.MEDIUM
    elif final_score <= settings.risk_high_max:
        level = RiskLevel.HIGH
    else:
        level = RiskLevel.CRITICAL

    # Determine primary threat category
    if final_score <= settings.risk_low_max:
        primary_category = ThreatCategory.NONE
    elif classifier_result.is_degraded:
        primary_category = ThreatCategory.CLASSIFIER_FAILURE
    elif rule_matches:
        # Highest severity rule category
        sorted_matches = sorted(rule_matches, key=lambda m: m.severity_weight, reverse=True)
        primary_category = sorted_matches[0].category
    else:
        primary_category = classifier_result.predicted_category

    return RiskScoreResult(
        score=final_score,
        level=level,
        breakdown=breakdown,
        primary_category=primary_category,
    )
