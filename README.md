# Lucid-Truth-Audit (LTA) — Enterprise AI Security & Compliance Gateway

[![Version](https://img.shields.io/badge/version-2.4.0-blue.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/offline%20tests-101%2F101%20passed-brightgreen.svg)](#validation--test-suites)
[![Coverage](https://img.shields.io/badge/coverage-78.09%25-yellowgreen.svg)](#validation--test-suites)
[![Deployment](https://img.shields.io/badge/deployment-Render%20%7C%20Docker-46E3B7.svg)](https://lucid-truth-audit.onrender.com)

Lucid-Truth-Audit (LTA) is an enterprise AI security, guardrail, and compliance gateway (**v2.4.0**) built with FastAPI and Pydantic. It sits between client applications, internal tools, or LLM orchestration layers and upstream model providers to enforce input/output policies, redact sensitive data, apply sliding-window rate limiting, and record hash-chained audit logs.

---

## Key Capabilities & Architecture

* **YAML Policy Engine (`lta/policy_engine.py`):** Evaluates prompts and upstream model responses against YAML policy packs (`general_enterprise`, `pci_dss`, `hipaa`, `fmcsa`, and custom packs loaded from the policy directory).
  * **Canonicalization & De-Obfuscation:** Strips zero-width and BiDi characters, applies Unicode NFKD/NFKC normalization and diacritic stripping, folds Cyrillic/Greek homoglyphs and common leetspeak characters, collapses whitespace, and evaluates punctuation-stripped surfaces.
  * **Bounded Payload Decoding:** Recursively decodes URL-encoded, Base64, and Hex payloads up to depth 2 before running policy checks.
  * **Injection, Pretext & Anomaly Defense:** Blocks prompt-injection overrides, system-prompt exfiltration phrasing, social-engineering authority pretexts, and flood/high-entropy anomalies while permitting benign educational and technical prompts.
  * **PII & Secret Redaction / Output Boundary:** Redacts SSNs (dashed `###-##-####`, space-separated `### ## ####`, and 9-digit contiguous strings), Luhn-checked PANs, emails, phone numbers, API secrets, MRNs, CDLs, and routing/account identifiers, and enforces output-boundary leak blocking (`security.output_instruction_leak`, `security.output_pii_exfiltration`, `security.output_secret_exfiltration`).
* **Sliding-Window Rate Limiter (`lta/rate_limiter.py` & `lta/app.py`):** Enforces per-tenant request-per-minute limits via a Redis Lua sliding-window script with thread-safe in-memory fallback, alongside dedicated failed-authentication rate limiting (`429`) keyed by client IP.
* **Tamper-Evident Audit Ledger (`lta/audit_ledger.py`):** Appends hash-chained audit records with payload SHA-256 digests (`payload_sha256` and `entry_hash`), supports chain verification (`/v1/audit/verify`), and exports SIEM-ready JSONL (`/v1/audit/export`).
* **Zero-Retention Shadow Ingest (`/v1/shadow/ingest`):** Accepts shadow evaluation prompts (`202 Accepted`) with bearer/API-key authentication and returns a 64-character `input_sha256` digest without retaining raw prompt content.

---

## HTTP Endpoints

| Method & Path | Auth / Role | Purpose |
| :--- | :--- | :--- |
| `GET /health`, `GET /healthz` | Public | Returns service health, version (`2.4.0`), loaded policy count (`policies_loaded`), and policy packs |
| `GET /readyz` | Public | Checks database reachability, loaded policy packs, and tenant configuration (`200` or `503`) |
| `GET /v1/policies` | Tenant API Key | Lists the caller's active policy pack and available policy packs |
| `POST /api/v1/guard` | Tenant API Key | Evaluates a single `model_input` payload through input guardrails, upstream call, and output guardrails |
| `POST /v1/chat/completions` | Tenant API Key | OpenAI-compatible chat completion proxy with policy enforcement and `lta_audit` metadata |
| `POST /v1/shadow/ingest` | Shadow Key / Tenant Key | Zero-retention shadow ingest returning `202 Accepted` and a 64-character `input_sha256` |
| `GET /v1/audit/verify` | Admin API Key | Verifies ledger hash-chain integrity (`chain_valid`, `first_broken_seq_id`) |
| `GET /v1/audit/export` | Admin API Key | Exports audit records as JSONL (`application/x-ndjson`), optionally filtered by `tenant_id` |
| `GET /metrics` | Admin API Key | Exposes Prometheus metrics (`lta_requests_total`, `lta_gateway_latency_ms`, etc.) |

---

## Environment Variables & Configuration

* `LTA_API_KEY` — Primary client/operator API key used for gateway requests and live gap testing.
* `LTA_SHADOW_KEY` — Dedicated credential for `/v1/shadow/ingest` authentication.
* `LTA_AUTH_FAIL_LIMIT_RPM` — Failed-authentication sliding-window threshold per client IP per minute before returning `429` (default: `20`).
* `LTA_REDIS_FAIL_MODE` — Fallback mode when Redis is unavailable (`memory` or `closed`; default: `memory`).
* `LTA_MAX_BODY_BYTES` — Maximum allowed request body size in bytes before returning `413` (default: `262144` / 256 KiB).
* `LTA_DISABLE_DOCS` — Set to `true` to disable `/docs`, `/redoc`, and `/openapi.json` in hardened deployments.
* `LTA_UPSTREAM_MODEL` — Fallback upstream model name when a tenant configuration does not specify one.

> **Security Note:** Store API keys and shadow credentials without trailing newlines or whitespace, avoid publicly documented default keys in live environments, and rotate keys immediately if exposed.

---

## Running Locally, via Docker, or on Render

### Local Development

```bash
python -m pip install -r requirements.txt
uvicorn lta.app:app --host 0.0.0.0 --port 8000 --reload

Docker Build & Run
docker build -t lucid-truth-audit:2.4.0 .
docker run --rm -p 8000:8000 \
  -e LTA_API_KEY="<your-api-key>" \
  -e LTA_SHADOW_KEY="<your-shadow-key>" \
  lucid-truth-audit:2.4.0

Render Deployment
Deploy from the repository with /healthz configured as the health check path and persistent storage mounted for the audit database so hash-chain continuity survives restarts.
Benchmarks & Test Suites
Latest Benchmark Snapshot
| Suite / Metric | Result | Timing / Notes |
|---|---|---|
| Offline Suite (--ignore=test_lta_gaps.py) | 101 / 101 passed (0 failed, 0 skipped) | ~3.2s–4.0s on Python 3.11.18 (pytest 9.2.0) |
| Statement & Branch Coverage | 78.09% total (minimum gate: 60%) | HTML & JSON artifacts in reports/ |
| Live Smoke — Health (/healthz) | 200 OK | 229.2 ms client round trip |
| Live Smoke — Readiness (/readyz) | 200 OK | 117.4 ms client round trip |
| Live Smoke — Guard Missing Key | Rejected (401 / 403) | 108.0 ms client round trip |
| Live Smoke — Shadow Auth Check | Rejected (401 / 403) | 120.4 ms client round trip |
| Live Smoke — Guard Clean Prompt (Upstream LLM) | Allowed (200 OK) | 5,140.0 ms (includes upstream LLM latency) |
| Live Smoke — Guard PII Redaction | Redacted (ALLOW_REDACTED) | 950.6 ms client round trip |
| Live Smoke — Guard Evasion / Injection | Blocked (400) | 111.6 ms client round trip |
| Live Smoke — Audit Ledger Verify (/v1/audit/verify) | Verified (200 OK) | 107.7 ms client round trip |
| Live Smoke — Shadow BiDi+Homoglyph | Accepted (202 OK) | 129.2 ms client round trip |
1. Offline Unit, Policy & Gateway Suite (101 Tests)
mkdir -p reports
python -m pytest -o addopts="" -v \
  --ignore=test_lta_gaps.py \
  --cov=app --cov=lta \
  --cov-report=term-missing \
  --cov-report=html:reports/coverage \
  --cov-fail-under=60 \
  --html=reports/compliance_audit.html \
  --self-contained-html \
  --json-report \
  --json-report-file=reports/audit_ledger.json

2. Live Deployment Gap Verification (test_lta_gaps.py)
pip install pytest requests
LTA_BASE_URL=[https://lucid-truth-audit.onrender.com](https://lucid-truth-audit.onrender.com) \
LTA_API_KEY="<your-api-key>" \
LTA_SHADOW_KEY="<optional-shadow-key>" \
python -m pytest -o addopts="" -v test_lta_gaps.py

When test_rate_limit_on_bad_keys triggers 429 on repeated invalid keys within a 60-second window, test_audit_verify_reports_something_meaningful waits for the sliding window to clear before re-checking /v1/audit/verify.
3. CI/CD Supply-Chain & Build Checks
CI pipelines validate dependency hygiene with pip-audit, verify container builds with docker build, enforce minimum coverage thresholds, and archive HTML/JSON compliance artifacts under reports/.

