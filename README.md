# Lucid-Truth-Audit (LTA) — Enterprise Gateway v2.3 Hardened

[![Lucid Truth Audit CI](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions)
![Pytest Suite](https://img.shields.io/badge/Pytest_Suite-62%2F62_Passing-10b981?style=flat&logo=pytest&logoColor=white)
![Local Latency](https://img.shields.io/badge/Local_p95_Latency-3.67_ms-0ea5e9?style=flat)
![Local Throughput](https://img.shields.io/badge/Local_Throughput-295.4_req%2Fs-06b6d4?style=flat)
![Live API](https://img.shields.io/badge/Live_Endpoint-Render_v2.3-38bdf8?style=flat&logo=fastapi&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11.18-3776ab?style=flat&logo=python&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2_Strict-e92063?style=flat&logo=pydantic&logoColor=white)
![Compliance](https://img.shields.io/badge/Compliance-EU_AI_Act_%7C_ISO%2FIEC_42001_%7C_FMCSA-6366f1?style=flat)
![License](https://img.shields.io/badge/License-Proprietary_Evaluation_Only-amber?style=flat)

**Deterministic AI Security, Schema Guardrails, Hash-Chained Audit Logging, and Pre-Emptive Policy Enforcement for LLM APIs.**

Lucid-Truth-Audit (LTA) / Stickney-Audit-Mandate is a pre-emptive FastAPI and Pydantic v2 (`extra="forbid"`) security and compliance gateway. It sits ahead of LLM calls via an OpenAI-compatible proxy (`/v1/chat/completions`) and guard endpoint (`/api/v1/guard`) across upstream providers (OpenAI, Anthropic, Gemini, Ollama/vLLM), enforcing fail-closed authentication, per-tenant RBAC, recursive obfuscation canonicalization, PII/secret redaction, rate limiting, and a tamper-evident SHA-256 hash-chained audit ledger.

* **Live Interactive API & Swagger Docs:** https://lucid-truth-audit.onrender.com/docs
* **GitHub Repository:** https://github.com/stickneycorey1-source/Lucid-Truth-Audit-
* **License:** Proprietary (All Rights Reserved — Evaluation Only)

---

## Verified Metrics & Benchmark Snapshot

* **Automated CI Test Suite:** **62/62 passing** in GitHub Actions across `v2.1`–`v2.3` hardening cycles (including **18/18** enterprise integration tests plus legacy compliance suites; **55/55** passing in **654 ms** with zero failures or errors on Nov 20, 2026).
* **Local Gateway Benchmark:** **3.67 ms p95 latency** and **295.4 req/s** throughput across **200 requests** *(local benchmark scope; hosted Render/network/upstream LLM round-trips vary)*
* **Live Deployment Verification:** `GET /healthz` returns `200 OK` with **4** active policy packs; `GET /readyz` returns `200 OK` with `database_ok: true`; unauthenticated `/metrics` and `/v1/chat/completions` fail closed with `403 Forbidden`.
* **Policy Packs (`v2.3`):** `general_enterprise`, `logistics_fmcsa`, `healthcare_hipaa`, and `finance_pci`.

---

## Defense-in-Depth Architecture

```text
Incoming Request ─► [1. Fail-Closed Auth & Per-Tenant RBAC: SHA-256 API Keys]
├─► Missing / Invalid Key / Unauth System Turn ─► 403 Forbidden (Policy downgrade blocked)
├─► Missing Server Secret ──────────────────────► 500 Fail-Closed
▼
[2. Payload Caps & Strict Schema: Pydantic v2 (extra="forbid")]
├─► >256 KB Body / >50 Messages / Bad Shape ──► 422 Unprocessable Entity
▼
[3. Sliding-Window Rate Limiter & Recursive Canonicalization]
├─► Rate / Flood / Entropy Limit Exceeded ─────► 429 Too Many Requests
├─► NFKC / Zero-Width / Homoglyphs / B64 / Hex ► 400 Bad Request (Injection blocked)
▼
[4. Policy Enforcement & Provider-Agnostic Proxy (/v1/chat/completions | /api/v1/guard)]
├─► YAML Policy Rules (Enterprise / FMCSA / HIPAA / PCI) + Upstream Adapters
▼
[5. Output Boundary Validator & SHA-256 Hash-Chained Audit Ledger]
├─► Instruction / Secret / PII Leak / Redaction ─► Blocked / Redacted + SIEM JSONL + /metrics
