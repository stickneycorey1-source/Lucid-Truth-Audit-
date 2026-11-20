# Lucid-Truth-Audit (LTA)

[![Lucid Truth Audit CI](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions)
![Test Suite](https://img.shields.io/badge/Pytest_Guardrail_Suite-55%2F55_Passing-10b981?style=flat&logo=pytest&logoColor=white)
![Live API](https://img.shields.io/badge/Live_Endpoint-Render_Active-38bdf8?style=flat&logo=fastapi&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11.18-3776ab?style=flat&logo=python&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2_Strict-e92063?style=flat&logo=pydantic&logoColor=white)
![Compliance](https://img.shields.io/badge/Compliance-EU_AI_Act_%7C_ISO%2FIEC_42001-6366f1?style=flat)
![License](https://img.shields.io/badge/License-MIT-slate?style=flat)

**Deterministic AI Compliance, Schema Guardrails, and Automated Red-Team Verification for Production LLM APIs.**

Lucid-Truth-Audit (LTA) wraps LLM endpoints in a defense-in-depth FastAPI and Pydantic v2 security gateway. Every request passes through fail-closed authentication, sliding-window rate limiting, Unicode/encoding canonicalization, anomaly detection, PII redaction, and strict output boundary validation—generating auditable compliance artifacts aligned with **EU AI Act (Regulation (EU) 2024/1689)** and **ISO/IEC 42001** risk-management standards.

* **Live Interactive API & Swagger Docs:** [https://lucid-truth-audit.onrender.com/docs](https://lucid-truth-audit.onrender.com/docs)
* **GitHub Repository:** [https://github.com/stickneycorey1-source/Lucid-Truth-Audit-](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-)
* **Enterprise Evaluation:** Request a 30-Day Shadow Pilot via repository Issues or direct contact with Lucid Truth.

---

## Defense-in-Depth Architecture

```text
Incoming Request ─► [1. Fail-Closed Auth & Sliding-Window Rate Limiter]
                        ├─► Missing Server Secret ───────────► 503 Service Unavailable (security.configuration_error)
                        ├─► Missing / Invalid Key ───────────► 403 Forbidden (security.authentication_rejected)
                        ├─► Rate Limit Exceeded ─────────────► 429 Too Many Requests
                        ▼
                    [2. Strict Input Schema: Pydantic v2 (extra="forbid")]
                        ├─► Unexpected Fields / Bad Shapes ──► 422 Unprocessable Entity
                        ▼
                    [3. Canonicalization, Anomaly & Social-Engineering Gateway]
                        ├─► Zero-Width / Cyrillic / B64 / Hex ► 400 Bad Request (security.input_blocked)
                        ├─► Floods / High-Entropy / Role Spoof► 400 / 422 Blocked
                        ▼
                    [4. Structural Sandwich Isolation & LLM Execution]
                        ├─► XML <user_input> Boundary + Terminal Non-Disclosure Directive
                        ▼
                    [5. Output Boundary Validator & PII Redaction: Pydantic v2]
                        ├─► Instruction / Secret Leak ───────► 502 Bad Gateway (Output boundary triggered)
                        └─► Validated & Redacted Payload ────► 200 OK + Redacted Audit Ledger
