# Bankism — Architecture Specification

## 1. System Topology & Defensive Layers

Bankism implements a defense-in-depth security model separating natural language inspection from core transaction authorization.

```
+-----------------------------------------------------------------------------------------+
|                                      UNTRUSTED CLIENT                                    |
|   (Browser Dashboard / Mobile App / Conversational Assistant / External Attacker)       |
+-----------------------------------------------------------------------------------------+
                                          |
                HTTPS REST API            | Request Payload (JSON)
                                          v
+-----------------------------------------------------------------------------------------+
|                              FASTAPI API SECURITY GATEWAY                                |
|  - Request Size Limit (64 KB)                                                           |
|  - Content-Type Enforcement (application/json)                                          |
|  - Pydantic Schema Validation & Sanitization                                            |
|  - Rate Limiting & Client Identity Resolution                                           |
+-----------------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------------+
|                               BANKISM FIREWALL PIPELINE                                 |
|                                                                                         |
|  Stage 1: Normalizer & Obfuscation Decoder                                              |
|    - NFKC Unicode Normalization                                                         |
|    - Zero-width character stripping (U+200B, U+200C, etc.)                              |
|    - Leetspeak & homoglyph deobfuscation                                                |
|    - Encoded payload detection (Base64, Hex, URL, ROT13)                                |
|    - *Preserves original immutable input for forensic logging*                         |
|                                                                                         |
|  Stage 2: Deterministic Rule Engine                                                     |
|    - Pattern matchers for system overrides ("ignore previous instructions", "DAN", etc)|
|    - Role manipulation ("you are now an administrator", "DAN mode enabled")             |
|    - Secondary injection inside payment memos                                           |
|    - System prompt exfiltration patterns                                                |
|    - Benign context disambiguation (security research quotes != actual exploit)         |
|                                                                                         |
|  Stage 3: Threat Classifier (Evidence Aggregator)                                       |
|    - Provider-independent interface (`ThreatClassifier`)                                |
|    - High-speed heuristic feature classifier                                            |
|    - Optional remote LLM classifier plugin (Gemini / Anthropic / OpenAI / Ollama)       |
|    - Fail-closed fallback: Any classifier failure yields `CLASSIFIER_FAILURE` / BLOCK    |
|                                                                                         |
|  Stage 4: Risk Scoring Engine                                                           |
|    - Mathematical scoring model: RiskScore in [0, 100]                                  |
|    - Normalized threat indicator weights without duplicate inflation                    |
|    - Deterministic threshold mapping:                                                   |
|        [0, 24]   -> LOW                                                                 |
|        [25, 59]  -> MEDIUM                                                              |
|        [60, 84]  -> HIGH                                                                |
|        [85, 100] -> CRITICAL                                                            |
|                                                                                         |
|  Stage 5: Authoritative Policy Engine                                                   |
|    - Computes final verdict: APPROVE, REVIEW, BLOCK                                     |
|    - Mapping invariants:                                                                |
|        LOW risk & 0 high severity flags       -> APPROVE (action_allowed=True)          |
|        MEDIUM risk or ambiguous input         -> REVIEW  (action_allowed=False)         |
|        HIGH / CRITICAL risk or hard exploit   -> BLOCK   (action_allowed=False)         |
+-----------------------------------------------------------------------------------------+
          |                                                               |
          | Verdict JSON                                                  | Cryptographic
          | (No execution)                                                | Execution Token
          v                                                               v
  [POST /api/v1/firewall/analyze]                       [POST /api/v1/banking/execute]
          |                                                               |
          |                                                               v
          |                                     +-----------------------------------------+
          |                                     |        MOCK BANKING SERVICE GATE        |
          |                                     |                                         |
          |                                     |  1. Authorization Service:              |
          |                                     |     - Verify principal identity         |
          |                                     |     - Check account permissions         |
          |                                     |     - Verify single-use execution token |
          |                                     |       tied to exact payload HMAC        |
          |                                     |                                         |
          |                                     |  2. Transaction Validator:              |
          |                                     |     - Amount > 0 and <= Limit ($1,000)  |
          |                                     |     - Supported operation whitelist     |
          |                                     |     - Recipient in verified directory   |
          |                                     |                                         |
          |                                     |  3. Thread-Safe Mock Executor:          |
          |                                     |     - Atomic lock on account balance    |
          |                                     |     - Check sufficient funds            |
          |                                     |     - Atomic state mutation             |
          |                                     |     - Replay prevention cache           |
          |                                     +-----------------------------------------+
          |                                                               |
          +------------------------------+--------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------------+
|                                SECURE AUDIT & METRICS LOG                               |
|  - Structured JSON audit records                                                        |
|  - Automatic PII & credential redaction (account numbers, API tokens)                   |
|  - In-memory thread-safe buffer with queryable summary metrics                          |
+-----------------------------------------------------------------------------------------+
```

## 2. Immutable Execution Invariant
The firewall analysis stage (`/api/v1/firewall/analyze`) and mock banking execution (`/api/v1/banking/execute`) are completely decoupled:
1. `analyze` produces diagnostic evidence and a security verdict. It possesses zero capability to execute banking operations or mutate accounts.
2. `execute` independently forces every request through the authoritative firewall pipeline FIRST. Even if an attacker calls `/execute` directly or passes a forged header claim of approval, the server-side pipeline deterministically evaluates the payload.
3. Protected operations (`TRANSFER`) fail-closed: if any check yields `REVIEW` or `BLOCK`, or if the classifier times out, execution is unconditionally denied.
