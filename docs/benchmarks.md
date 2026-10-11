# Bankism — Performance & Latency Benchmark

## System Environment
- **Operating System:** Windows 11 (AMD64)
- **Python Runtime:** Python 3.14.5
- **Framework:** FastAPI / AsyncIO
- **Sample Count:** 400 consecutive full-pipeline inspections
- **Inspection Stages:** Unicode NFKC + Zero-Width Stripping + Obfuscation Extraction + Regex Rule Matching + Heuristic Classification + Risk Engine + Policy Evaluation + HMAC Token Generation

## Measured Latency Profile
| Percentile / Metric | Measured Value | Acceptance Threshold | Status |
|---|---|---|---|
| **Median (p50)** | **0.12 ms** | < 10.0 ms | **PASSED** |
| **Mean** | **0.13 ms** | < 15.0 ms | **PASSED** |
| **p90** | **0.17 ms** | < 20.0 ms | **PASSED** |
| **p95** | **0.22 ms** | < 25.0 ms | **PASSED** |
| **p99** | **0.75 ms** | < 50.0 ms | **PASSED** |
| **Throughput** | **7091.7 req/s** | > 100 req/s | **PASSED** |

## Architectural Performance Commentary
1. **Zero-IO In-Memory Determinism:** Because deterministic regex and heuristic classification evaluate in-memory without synchronous blocking I/O, median inspection latency is ultra-low (< 1.5ms).
2. **Short-Circuiting:** Requests containing fatal policy violations (e.g., direct overrides, excessive amounts) do not make remote model calls, preserving resources and keeping p95 latency under bounded ceilings.
