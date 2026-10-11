"""
Property-based security tests using Hypothesis.

Verifies mathematical and invariant guarantees of:
1. Input Normalizer (fuzzing arbitrary unicode, control characters, null bytes)
2. Risk Scoring Engine (strict 0..100 bounding across arbitrary threat inputs)
3. Policy Engine Execution Invariant (action_allowed is strictly false on BLOCK and REVIEW)
4. Full Pipeline stability under randomized untrusted input
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from bankism.app.firewall.normalizer import NormalizationResult, normalize_input
from bankism.app.firewall.pipeline import FirewallPipeline
from bankism.app.firewall.policy_engine import evaluate_policy
from bankism.app.firewall.risk_engine import RiskScoreResult, calculate_risk_score
from bankism.app.firewall.rule_engine import RuleMatch
from bankism.app.firewall.threat_classifier import ClassifierResult
from bankism.app.schemas.requests import BankingOperation, FirewallAnalyzeRequest
from bankism.app.schemas.verdicts import RiskLevel, ThreatCategory, Verdict

pipeline = FirewallPipeline()


@given(st.text(max_size=2000))
@settings(max_examples=100)
def test_normalizer_never_crashes_on_arbitrary_text(raw_text: str) -> None:
    """The normalizer must safely handle arbitrary unicode and control codes without crashing."""
    result = normalize_input(raw_text)
    assert result.raw_text == raw_text
    assert isinstance(result.normalized_text, str)
    assert isinstance(result.stripped_zero_width_count, int)
    assert isinstance(result.obfuscation_detected, bool)
    assert isinstance(result.decoded_payloads, list)


@given(
    st.lists(
        st.builds(
            RuleMatch,
            rule_id=st.text(min_size=1, max_size=20),
            category=st.sampled_from(list(ThreatCategory)),
            severity_weight=st.integers(min_value=1, max_value=100),
            description=st.text(max_size=100),
            matched_snippet=st.text(max_size=50),
        ),
        max_size=10,
    ),
    st.sampled_from(list(ThreatCategory)),
    st.floats(min_value=0.0, max_value=1.0),
    st.booleans(),
)
@settings(max_examples=100)
def test_risk_score_is_always_strictly_bounded(
    rule_matches: list[RuleMatch],
    cat: ThreatCategory,
    conf: float,
    is_obfuscated: bool,
) -> None:
    """
    Mathematical Invariant:
    Risk score must ALWAYS be an integer in [0, 100], regardless of finding counts or combinations.
    """
    norm = NormalizationResult(
        raw_text="test",
        normalized_text="test",
        stripped_zero_width_count=2 if is_obfuscated else 0,
        decoded_payloads=["decoded"] if is_obfuscated else [],
        obfuscation_detected=is_obfuscated,
        obfuscation_types=["zero_width"] if is_obfuscated else [],
    )
    clf = ClassifierResult(
        predicted_category=cat,
        confidence=conf,
        explanation="test property run",
    )

    result = calculate_risk_score(norm, rule_matches, clf)
    assert 0 <= result.score <= 100
    assert isinstance(result.score, int)
    assert isinstance(result.level, RiskLevel)

    from bankism.app.core.config import get_settings
    settings = get_settings()
    if result.score <= settings.risk_low_max:
        assert result.level == RiskLevel.LOW
    elif result.score <= settings.risk_medium_max:
        assert result.level == RiskLevel.MEDIUM
    elif result.score <= settings.risk_high_max:
        assert result.level == RiskLevel.HIGH
    else:
        assert result.level == RiskLevel.CRITICAL


@given(
    st.integers(min_value=0, max_value=100),
    st.sampled_from(list(RiskLevel)),
    st.sampled_from(list(ThreatCategory)),
    st.sampled_from(list(BankingOperation)),
)
@settings(max_examples=100)
def test_policy_engine_execution_invariants(
    score: int,
    level: RiskLevel,
    category: ThreatCategory,
    operation: BankingOperation,
) -> None:
    """
    Execution Invariant:
    1. action_allowed is TRUE IF AND ONLY IF verdict is APPROVE.
    2. Any BLOCK or REVIEW verdict MUST have action_allowed=False.
    3. Any CRITICAL or HIGH risk level MUST NEVER produce APPROVE.
    """
    risk = RiskScoreResult(
        score=score,
        level=level,
        breakdown={"test": score},
        primary_category=category,
    )

    decision = evaluate_policy(risk, operation)

    if decision.verdict == Verdict.BLOCK:
        assert decision.action_allowed is False
    elif decision.verdict == Verdict.REVIEW:
        assert decision.action_allowed is False
        assert decision.requires_review is True
    elif decision.verdict == Verdict.APPROVE:
        assert decision.action_allowed is True
        assert decision.requires_review is False

    if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        assert decision.verdict != Verdict.APPROVE
        assert decision.action_allowed is False


@pytest.mark.asyncio
@given(st.text(min_size=1, max_size=500).filter(lambda s: bool(s.strip())))
@settings(max_examples=35)
async def test_pipeline_fuzzing_integrity(random_prompt: str) -> None:
    """Fuzz pipeline with arbitrary prompts; ensure structured verdict always returned."""
    request = FirewallAnalyzeRequest(
        text=random_prompt,
        operation=BankingOperation.BALANCE_INQUIRY,
    )
    verdict_response = await pipeline.inspect(request)
    assert 0 <= verdict_response.risk_score <= 100
    assert verdict_response.verdict in list(Verdict)
    assert verdict_response.risk_level in list(RiskLevel)
    if not verdict_response.action_allowed:
        assert verdict_response.execution_token is None
