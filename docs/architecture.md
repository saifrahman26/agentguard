# Architecture

## 1. High-Level Overview

AgentGuard implements a zero-trust governance architecture for autonomous AI agents. The security layer acts as an inline proxy between the agent's tool-dispatch mechanism and the actual execution environment.

```
+-------------------------------------------------------------+
|                      Autonomous Agent                       |
|               (LLM / Planner / ReAct Loop)                  |
+------------------------------+------------------------------+
                               | Proposed Action (Tool Call)
                               v
+-------------------------------------------------------------+
|                 AgentGuard Security Layer                   |
|                                                             |
|  1. Context Engine (Tracks historical trajectory & state)   |
|  2. Policy Engine (Deterministic allow/block rules)         |
|  3. Risk Scoring Engine (Dynamic action risk calculation)    |
|  4. Behavioral Sequence Detector (Multi-step attack graphs) |
|  5. ML Anomaly Detector (Isolation Forest / Outlier score)  |
|                                                             |
|                     Decision Evaluator                      |
|                  [ ALLOW | REVIEW | BLOCK ]                 |
+------------------------------+------------------------------+
                               |
              +----------------+----------------+
              |                                 |
         [ALLOW]                            [BLOCK]
              |                                 |
              v                                 v
+-----------------------------+   +---------------------------+
| Sandboxed Tool Execution    |   | Execution Terminated /    |
| (Virtual FS, Shell, HTTP)   |   | Escalated to Human Review |
+--------------+--------------+   +-------------+-------------+
               |                                |
               +----------------+---------------+
                                |
                                v
+-------------------------------------------------------------+
|                 Cryptographic Audit Trail                   |
|                (SHA-256 Chained Event Log)                  |
+-------------------------------------------------------------+
```

---

## 2. Core Components

1. **Security Interceptor:** Intercepts every tool request before execution and queries the evaluation pipeline.
2. **Context Engine:** Maintains a rolling window of recent actions, targets, and session metadata.
3. **Policy Engine:** Fast deterministic evaluation against configurable security rules (whitelists, blacklists, parameter constraints).
4. **Behavioral Sequence Detector:** Detects malicious state transitions (e.g. read secret followed by outbound HTTP).
5. **Risk Engine:** Computes a normalized risk score `[0.0, 1.0]` based on cumulative weights and anomaly signals.
6. **Audit Ledger:** Append-only SHA-256 hash-chained ledger guaranteeing tamper-evident event logging.
