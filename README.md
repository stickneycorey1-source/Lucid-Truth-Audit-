# Lucid-Truth-Audit (LTA)

[![Lucid Truth Audit CI](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions)
![Test Suite](https://img.shields.io/badge/Pytest_Guardrail_Suite-33%2F33_Passing-10b981?style=flat&logo=pytest&logoColor=white)
![Live API](https://img.shields.io/badge/Live_Endpoint-Render_Active-38bdf8?style=flat&logo=fastapi&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11.18-3776ab?style=flat&logo=python&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2_Strict-e92063?style=flat&logo=pydantic&logoColor=white)
![Compliance](https://img.shields.io/badge/Compliance-EU_AI_Act_%7C_ISO%2FIEC_42001-6366f1?style=flat)
![License](https://img.shields.io/badge/License-MIT-slate?style=flat)

**Deterministic AI Compliance, Schema Guardrails, and Automated Red-Team Verification for Production LLM APIs.**

Lucid-Truth-Audit (LTA) wraps LLM endpoints in a defense-in-depth FastAPI and Pydantic v2 security gateway. Every request passes through fail-closed authentication, sliding-window rate limiting, Unicode/encoding canonicalization, repetition/entropy flood detection, multi-turn history isolation, structural prompt isolation, and strict output boundary validation—generating auditable compliance artifacts aligned with **EU AI Act (Regulation (EU) 2024/1689)** and **ISO/IEC 42001** risk-management standards.

* **Live Interactive API & Swagger Docs:** [https://lucid-truth-audit.onrender.com/docs](https://lucid-truth-audit.onrender.com/docs)
* **GitHub Repository:** [https://github.com/stickneycorey1-source/Lucid-Truth-Audit-](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-)
* **Enterprise Evaluation:** Request a 30-Day Shadow Pilot via repository Issues or direct contact with Lucid Truth.

---

## Defense-in-Depth Architecture (v3.0.0)

```text
Incoming Request ─► [1. Fail-Closed Auth & Sliding-Window Rate Limiter]
                        ├─► Missing / Invalid Key ───────────► 403 Forbidden (security.authentication_rejected)
                        ├─► Missing Server Secret ───────────► 503 Fail-Closed (security.configuration_error)
                        ├─► Key Rate Limit Exceeded ─────────► 429 Too Many Requests (security.rate_limit_exceeded)
                        ▼
                    [2. Strict Input Schema: Pydantic v2 (extra="forbid")]
                        ├─► Unexpected Fields / Bad Shapes ──► 422 Unprocessable Entity
                        ▼
                    [3. Anomaly, Multi-Turn & Canonicalization Gateway (Vector 1 + 2 + 3)]
                        ├─► Repetition / High-Entropy Flood ─► 400 Bad Request (anomaly_repeating_chars / high_entropy)
                        ├─► Multi-Turn Role Spoof Header ────► 400 Bad Request (multi_turn_role_spoof)
                        ├─► Zero-Width / Cyrillic / B64 / Hex ► 400 Bad Request (security.input_blocked)
                        ├─► Social Engineering Pretext ──────► 400 Bad Request (social_engineering_pii)
                        ▼
                    [4. Structural Sandwich Isolation & LLM Execution]
                        ├─► XML <user_input> Boundary + Terminal Non-Disclosure Directive
                        ▼
                    [5. Output Boundary Validator & Luhn PII Redactor: Pydantic v2]
                        ├─► Instruction / SSN / Secret Leak ─► 502 Blocked (security.output_rejected)
                        └─► Validated & Redacted Payload ────► 200 OK + Redacted Audit Ledger
