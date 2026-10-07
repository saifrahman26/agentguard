# AgentGuard Research Log

This log documents hypotheses, experimental configurations, empirical results, failure modes, and engineering takeaways milestone by milestone.

---

## Research Entry Template

```text
Date: YYYY-MM-DD
Milestone: M<X>
Hypothesis:
What I changed:
Experiment:
Result:
What failed:
What I learned:
Next experiment:
```

---

## Entries

### Milestone 1: Core Infrastructure & Cryptographic Audit Trail
- **Date:** 2026-10-07
- **Milestone:** M1
- **Hypothesis:** A zero-trust middleware framework with deterministic SHA-256 hash chaining can record and verify action event trails without runtime performance degradation (<1ms overhead).
- **What I built:**
  - Standardized Pydantic data schemas (`AgentAction`, `SecurityDecision`, `AuditRecord`).
  - SQLite persistence layer for action logs and agent state.
  - SHA-256 cryptographic audit chaining with tamper-evident verification.
  - Structured JSON logging and modular settings management.
- **Experiment:** Verified cryptographic verification against tampered records, bit-flip attacks, and out-of-order logs across 47 automated tests.
- **Result:** 47/47 unit tests passed. Deterministic hash verification succeeds; payload modification is detected immediately.
- **What failed:** Initial serialization had dictionary key-order sensitivity causing hash verification discrepancies across test environments.
- **What I learned:** Canonical sorted JSON serialization with strict UTC ISO timestamp formats is critical for deterministic audit verification.
- **Next experiment:** Milestone 2 Agent Simulator with tool execution and virtual filesystem/shell sandboxing.

---

### Milestone 2: Agent Simulator & Sandboxed Tooling
- **Date:** 2026-10-07
- **Milestone:** M2
- **Hypothesis:** Simulating agent tool actions (filesystem, shell, network, package manager) in an in-memory virtual sandbox provides realistic evaluation of autonomous agent trajectories without endangering the host system.
- **What I built:**
  - Mock agent capable of executing predefined or dynamic action sequences.
  - Virtual sandbox filesystem, mock shell execution, mock network and package manager tools.
  - Synchronous interception hook connecting agent action proposal to security middleware.
- **Experiment:** Verified multi-step action sequences against virtual environments with interceptor callbacks (ALLOW, REVIEW, BLOCK).
- **Result:** Agent simulator executes sequences deterministically; intercepted blocked actions prevent tool execution and update state accordingly.
- **What failed:** Ensuring state synchronization between failed actions and downstream dependencies in a simulated agent trace.
- **What I learned:** Simulated environments must cleanly report tool errors back to the agent context without terminating the runtime orchestrator.
- **Next experiment:** Milestone 3 Security Middleware & Real-Time Interception Pipeline.

---

### Milestone 3: Security Middleware & Interceptor Pipeline
- **Date:** 2026-10-07
- **Milestone:** M3
- **Hypothesis:** A centralized security interceptor can evaluate proposed actions before tool execution, updating session context and audit ledgers atomically.
- **What I built:**
  - Synchronous and asynchronous security interceptor hooks.
  - Threat monitor coordinating policy, context, risk, and detection subsystems.
- **Experiment:** Tested interception pipelines with mock agents submitting varied action streams.
- **Result:** Interceptor successfully returns `ALLOW`, `REVIEW`, or `BLOCK` with zero state leakage.
- **What failed:** Handling unexpected exceptions inside custom tool wrappers without breaking the audit chain.
- **What I learned:** Audit records must record the interception decision even if the tool execution subsequently throws an error.
- **Next experiment:** Milestone 4 Deterministic Policy Engine.

---

### Milestone 4: Deterministic Policy Engine
- **Date:** 2026-10-07
- **Milestone:** M4
- **Hypothesis:** Rule-based permission sets and path/command/network pattern matchers can filter out high-confidence violations with sub-millisecond latency.
- **What I built:**
  - File path whitelist/blacklist matcher with path-traversal prevention.
  - Shell command whitelist and piped command decomposition.
  - Network domain whitelist and URL validator.
  - Package registry allowlist / blocklist.
- **Experiment:** Evaluated policy engine against edge cases including `../` traversals, command chaining (`&&`, `|`), and domain wildcards.
- **Result:** 100% of defined policy violations caught deterministically.
- **What failed:** Compound commands with nested quotes and subshells required recursive tokenization.
- **What I learned:** Basic string matching is insufficient for shell commands; tokenized command breakdown is required.
- **Next experiment:** Milestone 5 Dynamic Risk Scoring Engine.

---

### Milestone 5: Dynamic Risk Scoring Engine
- **Date:** 2026-10-07
- **Milestone:** M5
- **Hypothesis:** Multi-factor weighted risk scoring combining resource sensitivity, policy penalties, and session history provides nuanced decisions beyond binary blocklists.
- **What I built:**
  - Resource sensitivity classifier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`).
  - Context engine tracking historical actions within rolling time/action windows.
  - Risk score calculator normalizing cumulative penalty scores into `[0.0, 100.0]`.
- **Experiment:** Evaluated risk score outputs against escalating action sequences.
- **Result:** Risk scores accurately mapped to decision bands (`LOW` -> ALLOW, `MEDIUM` -> REVIEW, `HIGH`/`CRITICAL` -> BLOCK).
- **What failed:** Penalty inflation occurred when repeated benign actions shared overlapping context windows.
- **What I learned:** Exponential decay or temporal discounting prevents false positive inflation in prolonged sessions.
- **Next experiment:** Milestone 6 Behavioral Sequence Detection.

---

### Milestone 6: Behavioral Sequence Detection
- **Date:** 2026-10-07
- **Milestone:** M6
- **Hypothesis:** State-machine sequence matchers can detect multi-step attack graphs where each step is individually innocuous.
- **What I built:**
  - Behavioral sequence rules for credential exfiltration, prompt injection exploitation, privilege escalation, and destructive cascades.
  - Multi-event sliding window tracker with cross-tool event correlation.
- **Experiment:** Tested 10 multi-step attack patterns against the threat detector.
- **Result:** 100% detection rate across defined multi-step attack sequences with immediate blocking at the weaponization step.
- **What failed:** Distinguishing legitimate build scripts reading `.env.example` vs `.env` exfiltration.
- **What I learned:** Target path exactness and semantic context are essential to keep false positives low.
- **Next experiment:** Milestone 7 & 8 Attack Scenario and Legitimate Scenario Benchmark Suites.
