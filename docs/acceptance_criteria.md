# Bankism — Acceptance Criteria & Verification Matrix

The project is evaluated across six rigorous gates. Every gate specifies objective verification criteria:

---

## Gate 1: Code Quality
- [ ] Modular monolith structure separating normalizer, rule engine, threat classifier, risk engine, policy engine, banking validator, authorization, mock executor, and API routes.
- [ ] 100% type coverage with `mypy` running cleanly on all production modules.
- [ ] Clean linting with `ruff check` and formatting with `ruff format`.
- [ ] Exception handling returns structured, sanitized RFC 7807/FastAPI error responses without disclosing stack traces or filesystem paths.
- [ ] Zero raw prints; all operations logged through redacted structured logger.

## Gate 2: Security
- [ ] Hard deterministic boundary: Banking actions cannot execute without passing firewall, validation, and authorization stages.
- [ ] No client-controlled authorization: client cannot supply `action_allowed: true` or `role: "admin"` to force execution.
- [ ] Execution token binding: `/api/v1/banking/execute` verifies that execution tokens are cryptographically signed, bound to the exact payload hash, and single-use.
- [ ] Fail-closed behavior: Any classifier timeout or unexpected error forces `BLOCK` on protected operations.
- [ ] Replay / double-spending prevention: Transfers debit synthetic accounts atomically with lock verification and duplicate idempotency rejection.
- [ ] Sensitive data redaction: Account numbers, auth headers, and secrets are masked in logs and API error models.

## Gate 3: Efficiency
- [ ] Bounded input processing: Max payload size enforced (64 KB). Max text length enforced (4,000 characters).
- [ ] Rule engine evaluation runs in < 25ms p95 latency.
- [ ] Zero remote model calls on requests that fail deterministic checks (short-circuiting).
- [ ] Asynchronous non-blocking endpoints in FastAPI.

## Gate 4: Testing
- [ ] >=100 diverse, reproducible test cases in `datasets/evaluation_cases.json` across 18 threat and benign categories.
- [ ] Automated evaluation script `scripts/evaluate_dataset.py` computing True Positives, False Positives, True Negatives, False Negatives, Attack Detection Rate (Recall >= 90%), and False Positive Rate (<= 5%).
- [ ] Property-based fuzz testing using `Hypothesis` testing normalizer stability and risk score bounds [0, 100].
- [ ] Unit and integration test suite executing with `pytest`.
- [ ] Execution-boundary tests verifying 8 specific security assertions:
  1. Malicious requests blocked
  2. Unauthorized requests rejected
  3. Invalid transactions rejected
  4. Unresolved review cases cannot execute
  5. Classifier failures cannot bypass protected actions
  6. Blocked requests do not invoke mock executor
  7. Legitimate, authorized requests execute
  8. Repeated requests cannot duplicate transfer

## Gate 5: Accessibility
- [ ] Web dashboard built with semantic HTML elements (`<main>`, `<header>`, `<section>`, `<form>`, `<button>`).
- [ ] Explicit label associations for all inputs (`aria-label`, `<label for="...">`).
- [ ] Full keyboard navigation with visible focus rings (`tabindex="0"`, focus indicators).
- [ ] Status indicators convey meaning via text + icons + distinct badges (never color alone).
- [ ] ARIA live regions (`aria-live="polite"` or `"assertive"`) announce verdict updates to screen readers.
- [ ] High contrast ratios meeting WCAG AA standards (>= 4.5:1 for normal text).

## Gate 6: Problem Statement Alignment
- [ ] Direct inspection of untrusted natural language banking inputs.
- [ ] Detection and classification of prompt injections, jailbreaks, malicious memos, obfuscations, and unauthorized actions.
- [ ] Strict JSON verdict matching the required schema:
  - `request_id`: string
  - `verdict`: "APPROVE" | "BLOCK" | "REVIEW"
  - `risk_level`: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  - `risk_score`: int (0-100)
  - `threat_category`: string enum
  - `reason`: string
  - `action_allowed`: boolean
  - `requires_review`: boolean
- [ ] Real-time demonstrable dashboard for interactive evaluation.
