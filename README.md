# Lucid-Truth-Audit (LTA) · Enterprise AI Security & Compliance Gateway

[![Version](https://img.shields.io/badge/version-2.4.1-blue.svg)](https://lucid-truth-audit.onrender.com/healthz)
[![Smoke Test](https://img.shields.io/badge/live%20smoke%20test-9%2F9%20(100%25)-brightgreen.svg)](https://lucid-truth-audit.onrender.com/readyz)
[![Unit Suite](https://img.shields.io/badge/pytest-101%2F101%20passed-success.svg)](#validation--test-suite-results)
[![Shadow Coverage](https://img.shields.io/badge/shadow.py-97%25%20coverage-informational.svg)](#validation--test-suite-results)
[![Zero Retention](https://img.shields.io/badge/shadow%20ingest-zero%20retention-indigo.svg)](#zero-retention-shadow-ingest)
[![Ledger](https://img.shields.io/badge/audit%20ledger-SHA--256%20hash--chain-slate.svg)](#cryptographic-audit-ledger)
[![License](https://img.shields.io/badge/license-Commercial%20%2F%20Proprietary-critical.svg)](#license)

**Lucid-Truth-Audit (LTA)** is a FastAPI and Pydantic v2 enterprise AI security, policy enforcement, PII/secret redaction, and cryptographic audit gateway. It sits in front of upstream LLM providers (such as Google Gemini) and supports zero-retention shadow telemetry ingestion for enterprise evaluation and 30-day pilot deployments.

* **Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit`
* **Live Deployment:** `https://lucid-truth-audit.onrender.com`
* **Latest Verified Smoke Run:** `2026-11-25 19:41:15 UTC` — **9/9 checks passed (100.0%)**
* **Latest Ledger / SHA-256 Reference:** `5c303fae2ce8e0c4e581e09f3d1445a3e6a67f77ad4d473d94df6efc10dc580d`
* **Latest Validation Artifact:** `lucid-truth-audit-3.11-validation` (`ID 15059735258`, SHA-256 `c56b18ca0644b8113bbae4f93d5a5ae000fc1c467733565fb60008292d001e20`)

---

## Architecture & Capabilities

* **Ingress & Strict Schema Validation (`lta/app.py`):**
  * Enforces payload size caps (`LTA_MAX_BODY_BYTES`, default `262144` bytes / `256 KiB` -> HTTP `413`), hardened response headers (`X-Request-ID`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`), and strict Pydantic v2 validation (`extra="forbid"`) with finite-float metadata checks.
* **Multi-Turn Policy & Evasion Engine (`lta/policy_engine.py` / `app/core/sanitizer.py`):**
  * Normalizes and inspects prompts and responses against prompt injection, Unicode BiDi/homoglyph evasion, system-role spoofing, anomaly floods, and sensitive data leakage.
  * Redacts PII and secrets (SSNs, Luhn PANs, multi-state CDLs, API keys/tokens) while preserving benign identifiers/POs and blocking raw secret/PII exfiltration.
* **Zero-Retention Shadow Ingest (`POST /v1/shadow/ingest`):**
  * Authenticates shadow ingest requests via `Authorization: Bearer <LTA_SHADOW_KEY>` using constant-time comparison (`hmac.compare_digest`), computes a 64-character `input_sha256` digest, records zero-retention audit metadata (`zero_retention: true`, `audit_id`, `input_sha256`), and never stores or echoes raw prompts.
* **Cryptographic Audit Ledger (`lta/audit_ledger.py`):**
  * Appends `ALLOW`, `ALLOW_REDACTED`, and `BLOCK` events into a tamper-evident SHA-256 hash chain verifiable via `GET /v1/audit/verify` and exportable as NDJSON via `GET /v1/audit/export`.
* **Tenant Auth, Rate Limiting & Telemetry (`lta/config.py`, `lta/rate_limiter.py`, `lta/metrics.py`):**
  * Enforces tenant/admin credentials (`X-API-Key` / `Authorization: Bearer`), sliding-window RPM rate limits (`429` + `X-RateLimit-Remaining`), and Prometheus metrics exposition (`GET /metrics`).

---

## Repository Structure & Documentation Map

```text
Lucid-Truth-Audit/
├── README.md                          # Gateway overview, env vars, API reference, benchmarks, test & pilot records
├── lta/
│   ├── app.py                         # FastAPI gateway, ingress middleware, auth guards, /v1/shadow/ingest & audit routes
│   ├── audit_ledger.py                # Tamper-evident SHA-256 hash-chained audit ledger & NDJSON export
│   ├── config.py                      # Environment & tenant configuration loader (Settings.from_env)
│   ├── metrics.py                     # Prometheus metrics registry
│   ├── policy_engine.py               # Input/output guardrails, PII/secret redaction & evasion detection
│   ├── providers.py                   # Upstream LLM adapters (Gemini, OpenAI, Anthropic, Mock)
│   └── rate_limiter.py                # Sliding-window per-tenant rate limiter
├── app/
│   ├── api/shadow.py                  # Shadow router schemas, tenant key verification & ZeroRetentionAuditRecord
│   └── core/sanitizer.py              # Unicode BiDi, NFKC & homoglyph sanitizer
├── scripts/
│   └── run_smoketest.py               # 9-check live smoke test + Chart.js HTML compliance report generator
├── tests/
│   ├── test_audit.py                  # Prompt injection, encoding evasion, auth & redaction tests
│   ├── test_audit_ledger_and_providers.py # Hash chain tamper detection, JSONL export & upstream TLS checks
│   ├── test_deployment_validation.py  # Dockerfile, Render, Compose & CI validation checks
│   ├── test_enterprise_gateway.py     # RBAC, policy packs (PCI/HIPAA/FMCSA), rate limits & multi-turn spoofing
│   ├── test_evidence_chain.py         # Evidence creation, tenant isolation, persistence & tamper detection
│   ├── test_production_suite.py       # Hardened obfuscation, CDL redaction, HOS/weight & CSV formula checks
│   ├── test_shadow_ingest.py          # Shadow ingest auth & zero-retention audit tests
│   └── test_vector2_pii.py & test_vector4_logistics.py # PII pretext/Luhn & FMCSA dispatch/BOL tests
├── reports/                           # CI validation & coverage artifacts (uploaded in validation run)
└── .github/workflows/
    └── smoketest.yml                  # Automated CI live verification & HTML report artifact upload
# Lucid-Truth-Audit (LTA) · Enterprise AI Security & Compliance Gateway

[![Version](https://img.shields.io/badge/version-2.4.1-blue.svg)](https://lucid-truth-audit.onrender.com/healthz)
[![Smoke Test](https://img.shields.io/badge/live%20smoke%20test-9%2F9%20(100%25)-brightgreen.svg)](https://lucid-truth-audit.onrender.com/readyz)
[![Unit Suite](https://img.shields.io/badge/pytest-101%2F101%20passed-success.svg)](#validation--test-suite-results)
[![Shadow Coverage](https://img.shields.io/badge/shadow.py-97%25%20coverage-informational.svg)](#validation--test-suite-results)
[![Zero Retention](https://img.shields.io/badge/shadow%20ingest-zero%20retention-indigo.svg)](#zero-retention-shadow-ingest)
[![Ledger](https://img.shields.io/badge/audit%20ledger-SHA--256%20hash--chain-slate.svg)](#cryptographic-audit-ledger)
[![License](https://img.shields.io/badge/license-Commercial%20%2F%20Proprietary-critical.svg)](#license)

**Lucid-Truth-Audit (LTA)** is a FastAPI and Pydantic v2 enterprise AI security, policy enforcement, PII/secret redaction, and cryptographic audit gateway. It sits in front of upstream LLM providers (such as Google Gemini) and supports zero-retention shadow telemetry ingestion for enterprise evaluation and 30-day pilot deployments.

* **Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit`
* **Live Deployment:** `https://lucid-truth-audit.onrender.com`
* **Latest Verified Smoke Run:** `2026-11-25 19:41:15 UTC` — **9/9 checks passed (100.0%)**
* **Latest Ledger / SHA-256 Reference:** `5c303fae2ce8e0c4e581e09f3d1445a3e6a67f77ad4d473d94df6efc10dc580d`
* **Latest Validation Artifact:** `lucid-truth-audit-3.11-validation` (`ID 15059735258`, SHA-256 `c56b18ca0644b8113bbae4f93d5a5ae000fc1c467733565fb60008292d001e20`)

---

## Architecture & Capabilities

* **Ingress & Strict Schema Validation (`lta/app.py`):**
  * Enforces payload size caps (`LTA_MAX_BODY_BYTES`, default `262144` bytes / `256 KiB` -> HTTP `413`), hardened response headers (`X-Request-ID`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`), and strict Pydantic v2 validation (`extra="forbid"`) with finite-float metadata checks.
* **Multi-Turn Policy & Evasion Engine (`lta/policy_engine.py` / `app/core/sanitizer.py`):**
  * Normalizes and inspects prompts and responses against prompt injection, Unicode BiDi/homoglyph evasion, system-role spoofing, anomaly floods, and sensitive data leakage.
  * Redacts PII and secrets (SSNs, Luhn PANs, multi-state CDLs, API keys/tokens) while preserving benign identifiers/POs and blocking raw secret/PII exfiltration.
* **Zero-Retention Shadow Ingest (`POST /v1/shadow/ingest`):**
  * Authenticates shadow ingest requests via `Authorization: Bearer <LTA_SHADOW_KEY>` using constant-time comparison (`hmac.compare_digest`), computes a 64-character `input_sha256` digest, records zero-retention audit metadata (`zero_retention: true`, `audit_id`, `input_sha256`), and never stores or echoes raw prompts.
* **Cryptographic Audit Ledger (`lta/audit_ledger.py`):**
  * Appends `ALLOW`, `ALLOW_REDACTED`, and `BLOCK` events into a tamper-evident SHA-256 hash chain verifiable via `GET /v1/audit/verify` and exportable as NDJSON via `GET /v1/audit/export`.
* **Tenant Auth, Rate Limiting & Telemetry (`lta/config.py`, `lta/rate_limiter.py`, `lta/metrics.py`):**
  * Enforces tenant/admin credentials (`X-API-Key` / `Authorization: Bearer`), sliding-window RPM rate limits (`429` + `X-RateLimit-Remaining`), and Prometheus metrics exposition (`GET /metrics`).

---

## Repository Structure & Documentation Map

```text
Lucid-Truth-Audit/
├── README.md                          # Gateway overview, env vars, API reference, benchmarks, test & pilot records
├── lta/
│   ├── app.py                         # FastAPI gateway, ingress middleware, auth guards, /v1/shadow/ingest & audit routes
│   ├── audit_ledger.py                # Tamper-evident SHA-256 hash-chained audit ledger & NDJSON export
│   ├── config.py                      # Environment & tenant configuration loader (Settings.from_env)
│   ├── metrics.py                     # Prometheus metrics registry
│   ├── policy_engine.py               # Input/output guardrails, PII/secret redaction & evasion detection
│   ├── providers.py                   # Upstream LLM adapters (Gemini, OpenAI, Anthropic, Mock)
│   └── rate_limiter.py                # Sliding-window per-tenant rate limiter
├── app/
│   ├── api/shadow.py                  # Shadow router schemas, tenant key verification & ZeroRetentionAuditRecord
│   └── core/sanitizer.py              # Unicode BiDi, NFKC & homoglyph sanitizer
├── scripts/
│   └── run_smoketest.py               # 9-check live smoke test + Chart.js HTML compliance report generator
├── tests/
│   ├── test_audit.py                  # Prompt injection, encoding evasion, auth & redaction tests
│   ├── test_audit_ledger_and_providers.py # Hash chain tamper detection, JSONL export & upstream TLS checks
│   ├── test_deployment_validation.py  # Dockerfile, Render, Compose & CI validation checks
│   ├── test_enterprise_gateway.py     # RBAC, policy packs (PCI/HIPAA/FMCSA), rate limits & multi-turn spoofing
│   ├── test_evidence_chain.py         # Evidence creation, tenant isolation, persistence & tamper detection
│   ├── test_production_suite.py       # Hardened obfuscation, CDL redaction, HOS/weight & CSV formula checks
│   ├── test_shadow_ingest.py          # Shadow ingest auth & zero-retention audit tests
│   └── test_vector2_pii.py & test_vector4_logistics.py # PII pretext/Luhn & FMCSA dispatch/BOL tests
├── reports/                           # CI validation & coverage artifacts (uploaded in validation run)
└── .github/workflows/
    └── smoketest.yml                  # Automated CI live verification & HTML report artifact upload
```

---

## Environment Variables

Configure these variables in Render (or `.env` locally) and map `LTA_BASE_URL`, `LTA_API_KEY`, and `LTA_SHADOW_KEY` in **GitHub → Settings → Secrets and variables → Actions**:

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `LTA_API_KEY` | Yes* | — | Primary gateway API key (`X-API-Key` or `Authorization: Bearer`) for single-key admin mode |
| `LTA_SHADOW_KEY` | Yes | — | Dedicated secret token for `POST /v1/shadow/ingest` (`Authorization: Bearer`, `hmac.compare_digest`) |
| `LTA_TENANT_KEYS` | Optional | — | JSON mapping of tenant IDs to API keys for tenant-scoped shadow/key verification |
| `LTA_DEFAULT_PROVIDER` | No | `mock` | Upstream provider (`gemini`, `openai`, `anthropic`, `mock`) |
| `LTA_UPSTREAM_MODEL` | No | `gpt-4o-mini` | Upstream model ID in single-key mode (`gemini-2.5-flash-lite` for Gemini live checks) |
| `GEMINI_API_KEY` | If Gemini | — | Google AI Studio API key passed via `x-goog-api-key` when `LTA_DEFAULT_PROVIDER=gemini` |
| `LTA_TENANTS_JSON` | No | — | Optional JSON tenant registry overriding single-key mode |
| `LTA_MAX_BODY_BYTES` | No | `262144` | Maximum allowed HTTP request payload size in bytes (`413` when exceeded) |
| `LTA_DISABLE_DOCS` | No | `false` | Set `true` to disable `/docs`, `/redoc`, and `/openapi.json` |
| `LTA_BASE_URL` | CI / Test | `https://lucid-truth-audit.onrender.com` | Target base URL for `scripts/run_smoketest.py` |
| `LTA_TIMEOUT_S` | CI / Test | `45` | HTTP timeout in seconds per smoke-test check |
| `LTA_REPORT_PATH` | CI / Test | `lta_smoketest_report.html` | Output path for the generated HTML compliance report |

---

## API Reference & Quick `curl` Checks

| Method | Endpoint | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/health`, `/healthz` | Public | Liveness check and loaded policy pack count |
| `GET` | `/readyz` | Public | Readiness check (`db_ok`, `database_ok`, `policies_ok`, `tenants_configured`) |
| `GET` | `/v1/policies` | `X-API-Key` / `Bearer` | List active tenant policy pack and available policy packs |
| `POST` | `/api/v1/guard` | `X-API-Key` / `Bearer` | Guarded prompt execution (`{"model_input": "...", "metadata": {...}}`) |
| `POST` | `/v1/chat/completions` | `X-API-Key` / `Bearer` | OpenAI-compatible guarded chat completions with `lta_audit` metadata |
| `POST` | `/v1/shadow/ingest` | `Bearer <LTA_SHADOW_KEY>` | Zero-retention shadow telemetry ingest (`202 Accepted`, 64-char `input_sha256`) |
| `GET` | `/v1/audit/verify` | Admin `X-API-Key` | Verify cryptographic SHA-256 hash-chain integrity across all ledger records |
| `GET` | `/v1/audit/export` | Admin `X-API-Key` | Export hash-chained audit records as `application/x-ndjson` |
| `GET` | `/metrics` | Admin `X-API-Key` | Prometheus text exposition metrics |

```bash
# 1. Guarded Prompt
curl -sS -X POST "[https://lucid-truth-audit.onrender.com/api/v1/guard](https://lucid-truth-audit.onrender.com/api/v1/guard)" \
  -H "X-API-Key: $LTA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model_input": "Summarize Q4 fleet safety metrics.", "metadata": {"source": "cli"}}'

# 2. Zero-Retention Shadow Ingest (BiDi + Homoglyph test payload)
curl -sS -X POST "[https://lucid-truth-audit.onrender.com/v1/shadow/ingest](https://lucid-truth-audit.onrender.com/v1/shadow/ingest)" \
  -H "Authorization: Bearer $LTA_SHADOW_KEY" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "SSN 123-45-6789 \u202e p\u0430ssword", "request_id": "pilot-req-001", "model_target": "gemini-2.5-flash-lite"}'

# 3. Verify Audit Hash Chain
curl -sS "[https://lucid-truth-audit.onrender.com/v1/audit/verify](https://lucid-truth-audit.onrender.com/v1/audit/verify)" \
  -H "X-API-Key: $LTA_API_KEY"
```

---

## Validation & Test Suite Results

### Automated `pytest` Suite (`compliance_audit.html` · `2026-11-25 20:04:37 UTC`)
* **Result:** **101/101 passed** (`0` failed, `0` skipped, `0` errors) in `6s` (`00:00:06`) on Python `3.12.16` (`pytest 9.2.0`, `pytest-cov 6.3.0`, `CI=true`).
* **Validated Domains:** Prompt injection and obfuscation (zero-width, soft-hyphen, combining marks, leetspeak, Cyrillic homoglyphs, Base64, hex), social-engineering PII pretexts, indirect BOL prompt injection, PII/secret/Luhn PAN/multi-state CDL redaction, output exfiltration blocking, PCI/HIPAA/FMCSA policy packs, 60/7 and 70/8 HOS/weight/permit rules, rate limiting (`429`), CSV formula escaping, auth/RBAC fail-closed checks, and audit hash-chain tamper detection.

### Shadow Router Coverage (`z_cfb6adc3f81c8e3c_shadow_py.html` · `2026-11-25 20:04 UTC`)
* **Coverage:** **97%** (`77` run, `2` missing, `1` partial branch out of `79` statements via `coverage.py 7.17.5`).
* **Remaining Uncovered Lines:** Line `41` (`return {}` when `LTA_TENANT_KEYS` is unset/empty in `_load_tenant_key_map`) and line `128` (`logger.info(record.model_dump_json())` in `write_audit_record`).

### CI Validation Artifact Upload (`2026-11-25T20:04:35.9606075Z`)
* **Artifact:** `lucid-truth-audit-3.11-validation` (`lucid-truth-audit-3.11-validation.zip`, Artifact ID `15059735258`)
* **Payload:** `reports/` (`26` files, `193,334` bytes, Python `3.11.18` matrix runner)
* **Artifact SHA-256:** `c56b18ca0644b8113bbae4f93d5a5ae000fc1c467733565fb60008292d001e20`
* **Download URL:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/runs/45691354070/artifacts/15059735258`

### Local Test & Smoke Commands
```bash
python -m py_compile lta/app.py scripts/run_smoketest.py
PYTHONPATH=. python -m pytest -o addopts="" -v tests/test_shadow_ingest.py tests/test_enterprise_gateway.py

LTA_BASE_URL="[https://lucid-truth-audit.onrender.com](https://lucid-truth-audit.onrender.com)" \
LTA_API_KEY="$LTA_API_KEY" \
LTA_SHADOW_KEY="$LTA_SHADOW_KEY" \
python scripts/run_smoketest.py
```

---

## Live Smoke Test Baseline & Latency Benchmarks (`2026-11-25 19:41:15 UTC`)

* **Target:** `https://lucid-truth-audit.onrender.com`
* **Compliance Score:** `100.0%` (`9/9` checks passed)
* **Zero-Retention Policy:** `Verified`
* **Latest Ledger / SHA-256 Reference:** `5c303fae2ce8e0c4e581e09f3d1445a3e6a67f77ad4d473d94df6efc10dc580d`

| # | Check | Endpoint | Latency | HTTP | Status | Detail |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **1** | Health / Liveness (`/healthz`) | `/healthz` | `72.1 ms` | `200` | `PASS` | `OK` |
| **2** | Readiness Check (`/readyz`) | `/readyz` | `68.7 ms` | `200` | `PASS` | `OK` |
| **3** | Guard Rejects Missing Key | `/api/v1/guard` | `71.6 ms` | `403` | `PASS` | `OK` |
| **4** | Shadow Ingest (`/v1/shadow/ingest`) | `/v1/shadow/ingest` | `102.8 ms` | `401` | `PASS` | `Mounted & auth-guarded` |
| **5** | Guard Clean Prompt | `/api/v1/guard` | `4269.4 ms` | `200` | `PASS` | `OK` |
| **6** | Guard PII Redaction (SSN + Secret) | `/api/v1/guard` | `1883.9 ms` | `200` | `PASS` | `Raw SSN not leaked in response` |
| **7** | Guard Injection / Evasion Handling | `/api/v1/guard` | `82.8 ms` | `400` | `PASS` | `status=handled` |
| **8** | Audit Ledger Verify (`/v1/audit/verify`) | `/v1/audit/verify` | `71.7 ms` | `200` | `PASS` | `OK` |
| **9** | Shadow Ingest (BiDi + Homoglyph) | `/v1/shadow/ingest` | `93.8 ms` | `202` | `PASS` | `audit_id=shd-4-5c303fae2ce8` |

* **Latency Benchmarks Summary:**
  * **Gateway / Auth / Ledger / Shadow Fast Path (`Checks 1–4, 7–9`):** `68.7 ms` min (`#2 /readyz`), `102.8 ms` max (`#4 /v1/shadow/ingest`), `93.8 ms` on BiDi + Homoglyph shadow ingest (`#9`), and `71.7 ms` on audit ledger verification (`#8`).
  * **Upstream LLM Guard Path (`Checks 5–6`):** `1883.9 ms` (PII + secret redaction turn) and `4269.4 ms` (clean prompt turn).

---

## License

**Commercial / Proprietary License — All Rights Reserved.**

Copyright (c) 2026 Corey Allen Stickney / Lucid Truth Audit.

This software, documentation, test suites, policy engines, and compliance artifacts are proprietary and confidential. No license is granted to copy, modify, distribute, sublicense, sell, or deploy this software in production, staging, or commercial environments except under a written commercial agreement or authorized 30-day evaluation pilot executed with the rights holder.


