# Empirical Results

This document tracks quantitative metrics, benchmark runs, performance latency, and comparison tables as experiments are completed.

---

## Milestone 1 & 2 Preliminary Validation

| Metric | Target | Measured Value | Notes |
|---|---|---|---|
| Unit Test Pass Rate | 100% | 100% (47/47) | Testing schemas, audit chain, simulator, sandboxed tools |
| Audit Chaining Overhead | < 1.0 ms | ~0.08 ms | Deterministic SHA-256 with canonical JSON serialization |
| Tamper Detection Rate | 100% | 100% | Validated with modified payloads, altered previous hashes, and dropped events |
| Simulator Interception Success | 100% | 100% | Interceptor synchronously halts execution on BLOCK |

---

## Benchmark Results (Pending M9-M12)

*Detailed benchmark metrics (Detection Rate, False Positive Rate, Latency across 50 attack and 50 benign scenarios) will be populated upon completion of Milestone 9 & 10.*
