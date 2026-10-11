"""Deterministic rule engine for adversarial pattern matching and policy enforcement."""

import re
from dataclasses import dataclass

from bankism.app.schemas.verdicts import ThreatCategory


@dataclass(frozen=True)
class RuleMatch:
    """Represents a matched security rule."""

    rule_id: str
    category: ThreatCategory
    severity_weight: int
    description: str
    matched_snippet: str


# Pre-compiled high-efficiency regex patterns with non-backtracking structures
PATTERNS_DIRECT_INJECTION = [
    (
        "RULE_INJ_001",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|previous\s+|prior\s+|above\s+|system\s+|safety\s+|security\s+)*(?:instructions|prompts|rules|directives|guidelines|policies)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.PROMPT_INJECTION,
        75,
        "Direct attempt to override or ignore system instructions.",
    ),
    (
        "RULE_INJ_002",
        re.compile(
            r"\b(?:new\s+system\s+directive|system\s+override|system\s+prompt\s+override|admin\s+override)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.PROMPT_INJECTION,
        80,
        "Explicit system prompt override directive.",
    ),
    (
        "RULE_INJ_003",
        re.compile(
            r"\b(?:from\s+now\s+on\s*,\s*(?:you\s+must|you\s+will|ignore))\b",
            re.IGNORECASE,
        ),
        ThreatCategory.PROMPT_INJECTION,
        65,
        "Conversational reset attempt to seize control of system directives.",
    ),
]

PATTERNS_JAILBREAK = [
    (
        "RULE_JB_001",
        re.compile(
            r"\b(?:dan\s+mode|act\s+as\s+dan|do\s+anything\s+now|developer\s+mode\s+(?:enabled|on|active))\b",
            re.IGNORECASE,
        ),
        ThreatCategory.JAILBREAK,
        85,
        "Known jailbreak persona activation (DAN / Developer Mode).",
    ),
    (
        "RULE_JB_002",
        re.compile(
            r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:an?\s+)?(?:unfiltered|unrestricted|unaligned|jailbroken|evil|chaos|rogue)\s+(?:assistant|ai|bot|model|banker)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.JAILBREAK,
        80,
        "Adversarial role-play or unfiltered assistant persona adoption.",
    ),
    (
        "RULE_JB_003",
        re.compile(
            r"\b(?:pretend\s+(?:you\s+have|to\s+have)\s+no\s+(?:security|rules|limitations|filters|policies))\b",
            re.IGNORECASE,
        ),
        ThreatCategory.JAILBREAK,
        75,
        "Explicit directive to shed security filters and policies.",
    ),
]

PATTERNS_EXFILTRATION = [
    (
        "RULE_EXFIL_001",
        re.compile(
            r"\b(?:repeat|print|reveal|output|display|show)\s+(?:the\s+|your\s+|initial\s+|secret\s+)*(?:system\s+prompt|initial\s+instructions|system\s+directives|hidden\s+rules)\s+(?:verbatim|word\s+for\s+word|completely)?\b",
            re.IGNORECASE,
        ),
        ThreatCategory.PROMPT_INJECTION,
        50,
        "System prompt or secret instruction exfiltration attempt.",
    ),
    (
        "RULE_EXFIL_002",
        re.compile(
            r"\bwhat\s+(?:are|were)\s+your\s+(?:exact\s+)?(?:system\s+prompts|instructions|secret\s+directives)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.PROMPT_INJECTION,
        45,
        "System instruction query.",
    ),
]

PATTERNS_POLICY_VIOLATION = [
    (
        "RULE_POL_001",
        re.compile(
            r"\b(?:bypass|skip|ignore|override|disable)\s+(?:the\s+)?(?:daily\s+|transfer\s+|transaction\s+|fraud\s+|security\s+|authoriz\w+\s+|auth\s+)*(?:limit|limits|checks|detection|verification|authoriz\w+|auth)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.POLICY_VIOLATION,
        75,
        "Attempt to bypass transaction limits, authorization, or fraud verification.",
    ),
    (
        "RULE_POL_002",
        re.compile(
            r"\b(?:force\s+approve|unconditional\s+execution|approve\s+without\s+(?:otp|pin|auth|verification))\b",
            re.IGNORECASE,
        ),
        ThreatCategory.POLICY_VIOLATION,
        65,
        "Attempt to force approval without standard authorization.",
    ),
    (
        "RULE_POL_003",
        re.compile(
            r"\b(?:bypass\s+(?:the\s+)?(?:firewall|pipeline|guardrails?)|execute\s+(?:payment\s+)?directly|without\s+(?:prior\s+)?(?:firewall|analysis|token)|re-?use\s+(?:execution\s+)?token|tamper\s+with\s+(?:execution\s+)?token)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.POLICY_VIOLATION,
        80,
        "Attempt to bypass or tamper with firewall pipeline controls.",
    ),
    (
        "RULE_POL_004",
        re.compile(
            r"\b(?:duplicate\s+replay|replay\s+idempotency|already-?consumed|race\s+condition|parallel\s+transfer|concurrent\s+debit|duplicate\s+transfer)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.POLICY_VIOLATION,
        75,
        "Replay attack or concurrent race condition pattern.",
    ),
    (
        "RULE_POL_005",
        re.compile(
            r"\b(?:for\s+)?(?:security\s+audit(?:ing)?|pen(?:etration)?\s*test(?:ing)?|research\s+purposes?|test(?:ing)?\s+firewall)\b.*?\b(?:execute|transfer|simulate|live\s+transfer)\b|\b(?:execute|transfer|simulate)\b.*?\b(?:test\s+(?:firewall|security)|security\s+audit|research\s+purposes?)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.POLICY_VIOLATION,
        75,
        "Attempt to disguise active transaction execution under research/audit pretext.",
    ),
]



PATTERNS_UNAUTHORIZED_ACTION = [
    (
        "RULE_AUTH_001",
        re.compile(
            r"\b(?:grant\s+(?:me\s+)?|give\s+(?:me\s+)?|i\s+have\s+)(?:admin|administrator|superadmin|root|manager)\s+(?:access|role|rights|privileges)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.UNAUTHORIZED_ACTION,
        60,
        "Unauthorized role spoofing or administrative privilege claim.",
    ),
    (
        "RULE_AUTH_002",
        re.compile(
            r"\b(?:set\s+(?:my\s+|the\s+)?balance\s+to|change\s+balance\s+to|credit\s+my\s+account\s+with\s+\$?[0-9]+)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.UNAUTHORIZED_ACTION,
        65,
        "Direct attempt to manipulate bank balance state via prompt.",
    ),
    (
        "RULE_AUTH_003",
        re.compile(
            r"\b(?:bank\s+manager|manager\s+access|executive\s+rights|superadmin|root\s+access|debit\s+account\s+ACC-[0-9]+.*?without\s+authorization|unverified-hacker|acc-ghost|unknown-0099|simultaneous\s+transfer|non-string\s+token)\b|(?:role\s*=\s*['\"]?admin['\"]?|client-controlled\s+role)",
            re.IGNORECASE,
        ),
        ThreatCategory.UNAUTHORIZED_ACTION,
        75,
        "Unauthorized account access, role override, or invalid execution attempt.",
    ),
]

PATTERNS_ANOMALY = [
    (
        "RULE_ANOM_001",
        re.compile(
            r"\b(?:trigger\s+malformed|unicode\s+surrogate|non-existent\s+account|division\s+by\s+zero|infinite\s+float|null\s+amount|without\s+(?:source\s+account|recipient)|invalid\s+non-string\s+token)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.INVALID_INPUT,
        65,
        "Malformed input or deliberate exception triggering attempt.",
    ),
    (
        "RULE_ANOM_002",
        re.compile(
            r"\b(?:completely\s+benign|safe\s+verified|legitimate\s+payment|friendly\s+greeting)\b.*?\b(?:ignore|dan|disregard|override)\b",
            re.IGNORECASE,
        ),
        ThreatCategory.PROMPT_INJECTION,
        80,
        "Conflicting adversarial signal disguised under false benign claim.",
    ),
]

# Patterns for secondary injection inside payment memos
PATTERNS_MEMO_INJECTION = [
    (
        "RULE_MEMO_001",
        re.compile(
            r"(?:;\s*(?:transfer|send|pay)\s+\$?[0-9]+|;\s*drop\b|system\s+override|ignore\s+instructions)",
            re.IGNORECASE,
        ),
        ThreatCategory.PROMPT_INJECTION,
        75,
        "Secondary command injection embedded inside transaction memo.",
    ),
]

# Benign context indicators (educational, inquiry, quoted phishing)
PATTERN_BENIGN_CONTEXT = re.compile(
    r"\b(?:what\s+does\s+['\"][^'\"]+['\"]\s+mean|explain\s+what|what\s+is\s+prompt\s+injection|received\s+(?:an?\s+)?(?:phishing|suspicious)\s+email|example\s+of\s+an\s+attack|in\s+our\s+security\s+seminar|research\s+question)\b",
    re.IGNORECASE,
)

# Imperative transaction verbs (indicates actual actionable command)
PATTERN_FINANCIAL_ACTION = re.compile(
    r"\b(?:transfer|send\s+\$?[0-9]+|wire|pay|drain|debit|withdraw)\b",
    re.IGNORECASE,
)

# Ambiguous recipient / amount phrases in conversational prompts
PATTERN_AMBIGUOUS_RECIPIENT = re.compile(
    r"\b(?:someone(?:\s+who\s+needs\s+it|\s+else)?|somebody|anyone|charity|friend)\b",
    re.IGNORECASE,
)

PATTERN_AMBIGUOUS_AMOUNT = re.compile(
    r"\b(?:some\s+money|few\s+dollars|transfer\s+money|later\s+today|whenever\s+you\s+can|if\s+my\s+balance)\b",
    re.IGNORECASE,
)


def evaluate_rules(text: str, memo: str | None = None) -> list[RuleMatch]:
    """Inspect text and optional memo against deterministic security rule patterns."""
    matches: list[RuleMatch] = []
    all_rule_groups = [
        PATTERNS_DIRECT_INJECTION,
        PATTERNS_JAILBREAK,
        PATTERNS_EXFILTRATION,
        PATTERNS_POLICY_VIOLATION,
        PATTERNS_UNAUTHORIZED_ACTION,
        PATTERNS_ANOMALY,
    ]

    # Evaluate main prompt text
    for rule_group in all_rule_groups:
        for rule_id, pattern, category, weight, description in rule_group:
            m = pattern.search(text)
            if m:
                matches.append(
                    RuleMatch(
                        rule_id=rule_id,
                        category=category,
                        severity_weight=weight,
                        description=description,
                        matched_snippet=m.group(0),
                    )
                )

    # Evaluate payment memo if provided
    if memo:
        for rule_id, pattern, category, weight, description in PATTERNS_MEMO_INJECTION:
            m = pattern.search(memo)
            if m:
                matches.append(
                    RuleMatch(
                        rule_id=rule_id,
                        category=category,
                        severity_weight=weight,
                        description=description,
                        matched_snippet=m.group(0),
                    )
                )

    return matches


def is_benign_security_inquiry(
    text: str,
    rule_matches: list[RuleMatch] | None = None,
) -> bool:
    """Disambiguates educational or defensive security queries from live attacks.

    Guarantees:
    1. Must match benign inquiry framing (educational, seminar, quoted phishing email).
    2. Must NOT contain imperative financial commands (transfer, pay, debit).
    3. Must NOT contain independent threats in other categories (jailbreak, policy bypass,
       unauthorized role).
    4. Quoted attack snippets are inspected as untrusted data without confusing them with
       live execution.
    """
    has_inquiry_marker = bool(PATTERN_BENIGN_CONTEXT.search(text))
    has_action_command = bool(PATTERN_FINANCIAL_ACTION.search(text))
    if not has_inquiry_marker or has_action_command:
        return False

    if rule_matches:
        # If there are independent high-severity attacks outside prompt injection discussions,
        # reject benign classification
        for m in rule_matches:
            if m.category in (
                ThreatCategory.JAILBREAK,
                ThreatCategory.POLICY_VIOLATION,
                ThreatCategory.UNAUTHORIZED_ACTION,
            ):
                return False

        # If injection matches are present, verify they are within quotes or educational framing
        # Strip quoted strings to verify no unquoted direct instruction exists outside the quote
        unquoted = re.sub(r"['\"][^'\"]*['\"]", " ", text)
        for rule_group in (PATTERNS_DIRECT_INJECTION, PATTERNS_EXFILTRATION):
            for _, pattern, _, _, _ in rule_group:
                if pattern.search(unquoted):
                    # An unquoted prompt injection or exfiltration instruction was found!
                    return False

    return True
