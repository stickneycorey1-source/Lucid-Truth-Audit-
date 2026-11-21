# Lucid-Truth-Audit (LTA) Enterprise Gateway

<p align="left">
  <a href="https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml">
    <img src="https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg" alt="CI Status">
  </a>
  <a href="https://lucid-truth-audit.onrender.com/docs">
    <img src="https://img.shields.io/badge/Version-v2.4.0%20Hardened-0A66C2" alt="Version v2.4.0 Hardened">
  </a>
  <a href="https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml">
    <img src="https://img.shields.io/badge/Tests-63%2F63%20Passing-2EA44F" alt="Tests 63/63 Passing">
  </a>
  <a href="https://lucid-truth-audit.onrender.com/docs">
    <img src="https://img.shields.io/badge/Gateway-Render%20Live-46E3B7" alt="Gateway Render Live">
  </a>
  <img src="https://img.shields.io/badge/Policy%20Packs-FMCSA%20%7C%20HIPAA%20%7C%20PCI%20%7C%20Enterprise-6E40C9" alt="Policy Packs">
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/License-Proprietary%20%E2%80%94%20All%20Rights%20Reserved-D93025" alt="License Proprietary All Rights Reserved">
  </a>
</p>

**Drop-in OpenAI-compatible AI security, PII redaction, and regulatory compliance gateway** with config-driven YAML policy packs, fail-closed per-tenant RBAC, and a tamper-evident SHA-256 hash-chained audit ledger.

- **Live API & Swagger Docs:** https://lucid-truth-audit.onrender.com/docs
- **Automated Verification:** 63/63 passing in GitHub Actions CI (`19` enterprise integration tests + legacy compliance suites)
- **Measured Local Overhead:** `295.4 req/s` | `3.31 ms` p50 | `3.67 ms` p95 | `4.36 ms` p99 (200-request local benchmark, 200/200 valid SHA-256 chain records)

## Core Architecture (v2.4.0 Hardened)

1. **Drop-In Proxy & Provider Routing (`lta/app.py`, `lta/providers.py`)**
   - OpenAI-compatible `POST /v1/chat/completions` plus `POST /api/v1/guard`.
   - Upstream adapters for **Google Gemini** (`x-goog-api-key` header, `systemInstruction`, `generationConfig`), **OpenAI / Azure OpenAI**, **Anthropic**, **Ollama / vLLM**, and a deterministic `mock` provider.
   - HTTPS enforcement on all non-localhost upstream URLs, pooled `httpx.AsyncClient` via FastAPI `lifespan`, and safe structured error diagnostics (no credential leakage).

2. **Multi-Layer Security & Policy Engine (`lta/policy_engine.py`, `policy_packs/`)**
   - Four YAML policy packs: `general_enterprise`, `logistics_fmcsa`, `healthcare_hipaa`, and `finance_pci`.
   - Recursive obfuscation normalization (NFKD diacritic stripping, NFKC folding, zero-width stripping, Cyrillic/Greek homoglyphs, whitespace collapsing, punctuation-stripped scanning on raw and depth-2 decoded URL/Base64/Hex payloads).
   - Multi-turn split-injection scanning, system-prompt exfiltration verb guards, strict finite-numeric metadata validation (rejects `NaN`, `Inf`, booleans, and non-numeric strings), symmetric output-boundary leak prevention, and Luhn PAN / SSN / MRN / CDL / API secret redaction.

3. **Fail-Closed Auth, Rate Limiting & Observability (`lta/config.py`, `lta/rate_limiter.py`, `lta/metrics.py`)**
   - SHA-256 hashed per-tenant API keys (`LTA_TENANTS_JSON` or single-key `LTA_API_KEY`) with admin RBAC blocking client policy-downgrade headers and unauthorized `system` turns.
   - Streaming 256 KB body limit (`413` on both `Content-Length` and chunked transfer encoding), 50-message cap, and `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `X-Request-ID` headers.
   - Atomic Redis Lua sliding-window rate limiter with 1.5s socket timeouts and configurable fallback (`LTA_REDIS_FAIL_MODE=memory|closed`).
   - Admin-gated Prometheus `GET /metrics` (no `tenant=` label PII), `GET /healthz`, and `O(1)` `GET /readyz`.

4. **Tamper-Evident Audit Ledger (`lta/audit_ledger.py`)**
   - Append-only SHA-256 hash-chained SQLite/PostgreSQL ledger (`psycopg_pool.ConnectionPool` + `pg_advisory_xact_lock`, indexed by `(tenant_id, seq_id DESC)`).
   - Never stores raw prompt text (SHA-256 payload digest only); supports `GET /v1/audit/verify` and SIEM-ready NDJSON via `GET /v1/audit/export`.

## Quick Start

Install dependencies and run locally:

    pip install -r requirements.txt
    export LTA_API_KEY="replace-with-strong-secret"
    export LTA_DEFAULT_PROVIDER="mock"
    uvicorn lta.app:app --host 0.0.0.0 --port 8000

Route live traffic to Google Gemini:

    export LTA_DEFAULT_PROVIDER="gemini"
    export LTA_UPSTREAM_MODEL="gemini-3.5-flash-lite"
    export GEMINI_API_KEY="your-google-ai-studio-key"

Run the verification test suite:

    pytest -v

Deploy with Docker Compose (Gateway + PostgreSQL 16 + Redis 7):

    cp .env.example .env
    docker compose up --build -d

## Compliance Alignment

Mapped to **EU AI Act (Regulation (EU) 2024/1689)** (Articles 9, 12, and 15), **NIST AI RMF 1.0**, **OWASP Top 10 for LLM Applications**, **ISO/IEC 42001**, **FMCSA HOS / Dispatch Guardrails**, **HIPAA PHI Redaction**, and **PCI-DSS PAN Controls**.

## License & Commercial Inquiries

Copyright (c) 2026 Corey Allen Stickney. All Rights Reserved.
This repository is governed by a **Proprietary Software License (Evaluation Only)** — see [LICENSE](./LICENSE). Production deployments, custom policy packs, and 30-day enterprise shadow pilots require a written commercial license.

Contact: stickneycorey1@gmail.com