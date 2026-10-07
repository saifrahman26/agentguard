# AgentGuard — Zero-Trust Governance for Autonomous AI Agents

> **Research Prototype** — Context-aware security middleware and runtime behavioral governance for autonomous AI agents.

---

## Problem

Autonomous AI agents can read files, run shell commands, install third-party packages, and make outbound network requests. Conventional perimeter security and static command blocklists fail to capture multi-step attack chains where individual actions appear benign in isolation but malicious when evaluated in context (e.g., reading a config file followed by sending an external HTTP payload).

AgentGuard sits as an inline zero-trust proxy between the agent's tool-dispatch mechanism and execution environments, continuously analyzing behavioral sequences before actions execute.

---

## Threat Model

AgentGuard detects and defends against:
- **Indirect Prompt Injection:** Adversarial instructions in external retrieved data hijacking agent execution.
- **Credential Harvesting & Exfiltration:** Multi-step trajectories accessing sensitive files (`.env`, SSH keys) and transmitting them externally.
- **Destructive Command Sequences:** Unauthorized deletions, permission escalations (`chmod 777`, `sudo`), and system modifications.
- **Supply Chain Attacks:** Shadow package installations and unvetted external dependencies.

*Full details: [`docs/threat-model.md`](docs/threat-model.md)*

---

## Research Question

> **Can contextual behavioral sequence analysis and dynamic risk scoring detect dangerous autonomous agent behavior without unnecessarily restricting agent autonomy?**

*Full details: [`docs/research-question.md`](docs/research-question.md)*

---

## Architecture

```
AI Agent (LLM / ReAct Loop)
          ↓
AgentGuard Security Middleware
┌─────────────────────────────────┐
│  1. Context Engine              │
│  2. Policy Engine               │
│  3. Risk Scoring Engine         │
│  4. Behavioral Sequence Detector│
│  5. ML Anomaly Detection        │
└─────────────────────────────────┘
          ↓
DECISION: [ ALLOW | REVIEW | BLOCK ]
          ↓
Sandboxed Tool Execution (if ALLOW)
          ↓
SHA-256 Cryptographic Audit Ledger
          ↓
Live Monitoring & Reporting
```

*Full details: [`docs/architecture.md`](docs/architecture.md)*

---

## Implementation

- **Language & Runtime:** Python 3.11+ / FastAPI
- **Data Validation & Schemas:** Pydantic v2
- **Audit Integrity:** SHA-256 genesis-anchored cryptographic hash chaining
- **Persistence:** SQLite with asynchronous engine support
- **Testing:** Pytest & pytest-asyncio (108/108 passing tests)

```bash
# Setup virtual environment
cd backend
python -m venv venv
venv\Scripts\activate  # Windows (or source venv/bin/activate on Linux/macOS)

# Install dependencies
pip install -r requirements.txt

# Run test suite
pytest tests/ -v
```

---

## Experiments

We evaluate AgentGuard against synthetic benchmarks containing both legitimate software engineering trajectories and multi-step attack chains.

- **Experiment 1:** Cryptographic Audit Chain Tamper-Resistance & Serialization Invariance.
- **Experiment 2:** Interceptor Pipeline Latency & Sandbox State Isolation.
- **Experiment 3:** Behavioral Sequence Detection across Attack Matrices.

*Full details & logs: [`docs/experiments.md`](docs/experiments.md) & [`docs/research-log.md`](docs/research-log.md)*

---

## Results

| Metric | Target | Measured |
|---|---|---|
| Unit Test Pass Rate | 100% | 100% (108/108) |
| Audit Ledger Overhead | < 1.0 ms | ~0.08 ms |
| Tamper Detection Rate | 100% | 100% |
| Simulator Interceptor Reliability | 100% | 100% |
| Multi-Step Sequence Detection Recall | > 95% | 100% (unit suite) |

*Detailed benchmark metrics will be updated as experiments progress: [`docs/results.md`](docs/results.md)*

---

## Limitations

- Prototype currently operates in simulated sandboxed environments for benchmark safety.
- SHA-256 chaining guarantees audit tamper-evidence, not OS-level process isolation.
- Highly obfuscated payloads require multi-layered detection (heuristic + ML).

*Full details: [`docs/limitations.md`](docs/limitations.md)*

---

## Roadmap

- [x] **M1:** Core infrastructure, schemas & cryptographic audit ledger
- [x] **M2:** Agent simulator & sandboxed tool execution
- [x] **M3:** Security middleware & interceptor pipeline
- [x] **M4:** Deterministic policy engine
- [x] **M5:** Multi-factor risk scoring engine
- [x] **M6:** Behavioral sequence detection
- [ ] **M7:** Attack scenario suite
- [ ] **M8:** Legitimate scenario baseline
- [ ] **M9:** Automated benchmark runner
- [ ] **M10:** Experiment 1: Baseline evaluation
- [ ] **M11:** Machine learning anomaly detector
- [ ] **M12:** Comparative analysis (Rule vs ML vs Hybrid)
- [ ] **M13:** FastAPI REST & management endpoints
- [ ] **M14:** Web management dashboard
- [ ] **M15:** Real-time WebSocket monitoring
- [ ] **M16:** LLM explanation & incident summaries
- [ ] **M17:** Real-world agent adapter
- [ ] **M18:** Final research paper & evaluation report
