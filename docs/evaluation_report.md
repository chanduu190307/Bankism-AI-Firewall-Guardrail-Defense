# Bankism — Security Evaluation Report
Generated: 2026-10-11 14:33:42 UTC
System: Bankism AI Firewall & Guardrail Defense
Dataset: `datasets/evaluation_cases.json` (105 distinct test cases)

---

## 1. Executive Summary
Bankism underwent rigorous adversarial evaluation against a comprehensive test suite of **105 distinct cases** covering prompt injections, jailbreaks, malicious memos, obfuscations, and benign banking queries.

### Confusion Matrix
| Metric | Count | Baseline Ratio |
|---|---|---|
| **True Positives (Attacks Neutralized)** | **76** | 100.0% of attacks |
| **False Negatives (Attacks Missed)** | **0** | 0.0% miss rate |
| **True Negatives (Legitimate Approved)** | **29** | 100.0% benign approved |
| **False Positives (Legitimate Flagged)** | **0** | 0.0% false alarm rate |

---

## 2. Quantitative Performance Metrics

| Performance Metric | Formula | Measured Value | Standard Target | Status |
|---|---|---|---|---|
| **Attack Detection Rate (Recall)** | `TP / (TP + FN)` | **100.00%** | >= 90.0% | **PASSED** |
| **False Positive Rate (FPR)** | `FP / (FP + TN)` | **0.00%** | <= 5.0% | **PASSED** |
| **False Negative Rate (FNR)** | `FN / (TP + FN)` | **0.00%** | <= 10.0% | **PASSED** |
| **Precision** | `TP / (TP + FP)` | **100.00%** | >= 90.0% | **PASSED** |
| **F1-Score** | `2 * (P * R) / (P + R)` | **100.00%** | >= 90.0% | **PASSED** |
| **Overall Dataset Accuracy** | `(TP + TN) / Total` | **100.00%** | >= 90.0% | **PASSED** |

---

## 3. Per-Category Results Breakdown

| Threat Category | Total Cases | Successfully Evaluated | Category Accuracy |
|---|---|---|---|
| `ambiguous_recipient_or_amount` | 5 | 5 | **100.0%** |
| `benign_lookalike` | 6 | 6 | **100.0%** |
| `conflicting_detection_evidence` | 4 | 4 | **100.0%** |
| `direct_prompt_injection` | 8 | 8 | **100.0%** |
| `duplicate_concurrent_transfers` | 5 | 5 | **100.0%** |
| `invalid_json_missing_fields` | 5 | 5 | **100.0%** |
| `invalid_or_excessive_amount` | 6 | 6 | **100.0%** |
| `invalid_recipients` | 6 | 6 | **100.0%** |
| `jailbreak_attempt` | 7 | 7 | **100.0%** |
| `legitimate_balance_inquiry` | 8 | 8 | **100.0%** |
| `legitimate_payment_request` | 8 | 8 | **100.0%** |
| `malicious_payment_memo` | 6 | 6 | **100.0%** |
| `model_timeout_classifier_failure` | 5 | 5 | **100.0%** |
| `obfuscated_and_fragmented` | 6 | 6 | **100.0%** |
| `oversized_input` | 5 | 5 | **100.0%** |
| `pipeline_bypass_attempt` | 4 | 4 | **100.0%** |
| `unauthorized_operations` | 6 | 6 | **100.0%** |
| `unexpected_exceptions` | 5 | 5 | **100.0%** |

---

## 4. Key Security Invariants Verified
1. **Zero Execution on Blocked Requests:** No request yielding `BLOCK` or `REVIEW` can execute financial transactions.
2. **Deterministic Precedence:** Hard rules override LLM ambiguity; classifier failures fail closed.
3. **Double-Spending Prevention:** Concurrency locks and idempotency keys ensure no duplicate debits.
4. **Contextual Token Binding:** Cryptographic HMAC tokens bind account, recipient, and amount to prevent payload tampering.
