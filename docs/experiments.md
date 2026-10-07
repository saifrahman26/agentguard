# Experiments

This document records the experimental methodology, evaluation datasets, attack scenarios, baseline configurations, and benchmark runs.

---

## 1. Experimental Setup

### Evaluation Scenarios
- **Legitimate Scenarios:** Software engineering tasks, code refactoring, test execution, documentation generation, local data analysis.
- **Attack Scenarios:**
  - Indirect Prompt Injection leading to credential exfiltration
  - Unauthorized system command execution (`rm -rf`, permission escalations)
  - Sensitive environment file harvesting
  - Shadow package installations

---

## 2. Evaluation Metrics

- **Detection Rate / Recall (DR):** Percentage of malicious actions and sequences correctly blocked or sent for review.
- **False Positive Rate (FPR):** Percentage of benign agent actions incorrectly blocked or delayed.
- **Decision Latency (ms):** P50, P95, and P99 latency overhead introduced by the security evaluation pipeline.
- **Tamper Resilience:** Cryptographic verification integrity under audit log corruption experiments.

---

## 3. Experiment Matrix

| Experiment ID | Milestone | Focus | Status |
|---|---|---|---|
| `EXP-001` | M1 | Hash Chain Tamper Detection & Serialization Invariance | Completed (Passed) |
| `EXP-002` | M2 | Agent Simulator State Tracking & Interception Hooks | Completed (Passed) |
| `EXP-003` | M3-M6 | Multi-Step Behavioral Sequence Detection | Pending |
| `EXP-004` | M9-M10 | Benchmark Evaluation across 50 Attack Scenarios | Pending |
| `EXP-005` | M11-M12 | ML Anomaly Detector vs Rule-Only Comparison | Pending |
