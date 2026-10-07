# Limitations & Assumptions

## 1. System Assumptions
- **Host Security:** The host machine running the AgentGuard middleware process is assumed to be trusted and uncompromised.
- **Interception Guarantee:** In the simulator environment, tool execution is guaranteed to be routed through the middleware. In production integrations, the runtime host or agent framework (e.g. LangChain, AutoGen, custom ReAct loops) must strictly enforce proxying without bypasses.

---

## 2. Known Limitations
- **Indirect Evasion via Obfuscated Arguments:** Highly obfuscated shell commands (e.g., base64 encoded strings or dynamically assembled eval strings) may bypass simple static policy rules until processed by behavioral or ML stages.
- **Audit Ledger Storage:** The current SHA-256 hash chaining proves ledger tamper-evidence, but does not prevent malicious actors with OS root access from replacing the entire ledger database unless external notarization/remote replication is configured.
- **Simulation Sandbox Scope:** The current simulator uses an in-memory virtual filesystem and simulated network calls for safe benchmarking.
- **ML False Positives:** Novel, multi-tool legitimate developer workflows might trigger anomaly detection warnings and require human review approval.
