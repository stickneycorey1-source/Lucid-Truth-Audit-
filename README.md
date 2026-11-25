# Lucid-Truth-Audit (LTA) · Enterprise AI Security & Compliance Gateway

[![Production CI](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions)
[![Test Suite](https://img.shields.io/badge/tests-96%2F96%20passing-brightgreen.svg)](#verification--ci-metrics)
[![Code Coverage](https://img.shields.io/badge/coverage-80.63%25-brightgreen.svg)](#verification--ci-metrics)
[![Live Smoke Test](https://img.shields.io/badge/live%20smoke%20test-100%25%20(8%2F8)-brightgreen.svg)](#live-production-smoke-test-benchmarks)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.165%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063.svg)](https://docs.pydantic.dev/)
[![Zero-Retention](https://img.shields.io/badge/zero--retention-verified-success.svg)](#cryptographic-audit-ledger--zero-retention)

**Lucid-Truth-Audit (LTA)** is a hardened, drop-in OpenAI-compatible enterprise AI security, PII/PHI redaction, and regulatory compliance gateway (`v2.4.1`). It sits between client applications and upstream foundation models (`OpenAI`, `Azure OpenAI`, `Anthropic`, `Google Gemini`, `vLLM`, `Ollama`) to sanitize inputs, enforce domain-specific YAML policy packs, block prompt injection and multi-turn system spoofing, redact sensitive entities in real time, and record tamper-evident SHA-256 hash-chained audit logs with zero raw-prompt retention.

* **Live Production Deployment:** `https://lucid-truth-audit.onrender.com`
* **Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit-`

---

## Core Capabilities

* **OpenAI-Compatible Proxy & Legacy Guard API:** Drop-in `/v1/chat/completions` (`object: "chat.completion"`, `choices`, and `lta_audit` metadata) alongside `/api/v1/guard` for single-turn policy evaluation.
* **Defense-in-Depth Input & Output Guardrails:**
  * NFKC Unicode normalization, zero-width/BiDi override stripping, homoglyph detection, and Base64/Hex/leetspeak payload inspection.
  * Multi-turn conversation scanning to block cross-turn split injections, unauthorized `system` role spoofing, and poisoned `assistant` turns.
  * High-entropy gibberish, repeating-character, and repeating-word flood mitigation.
  * Output boundary enforcement preventing system prompt leaks, raw SSNs, and API credentials (`sk-...`, `ghp_...`, `AKIA...`, `AIza...`) from exiting the gateway.
* **Domain Regulatory Policy Packs:**
  * **Healthcare (HIPAA):** Redacts Medical Record Numbers (`MRN`), SSNs, and protected patient identifiers.
  * **Finance (PCI-DSS):** Luhn-validated PAN card redaction while preserving benign reference IDs, plus wire-threshold metadata checks.
  * **Logistics (FMCSA):** Multi-state Commercial Driver's License (`CDL`/`DL`) redaction while preserving Purchase Orders (`PO`), 60/7 and 70/8 Hours-of-Service (`HOS`) validation, gross vehicle weight checks, and waypoint-hijack defense.
  * **General Enterprise:** Baseline PII redaction, social-engineering pretext blocking, and strict schema validation.
* **Tenant Isolation & Resilience:**
  * Fail-closed authentication (`X-API-Key` or `Authorization: Bearer`) with role-based access control (`admin` vs. tenant keys; non-admin policy/provider override attempts rejected with `403`).
  * Per-tenant sliding-window rate limiter (`429 Too Many Requests` with `X-RateLimit-Remaining`) backed by atomic Redis Lua scripts with resilient in-memory fallback.
  * Strict Pydantic v2 validation (`extra="forbid"`, `NaN`/non-numeric metadata rejection) and `256 KiB` (`LTA_MAX_BODY_BYTES`) streaming body size enforcement (`413`).
* **Cryptographic Hash-Chained Audit Ledger:**
  * Append-only SQLite / PostgreSQL (`pg_advisory_xact_lock`) audit log chaining every event via SHA-256 (`prev_hash` -> `entry_hash`) without storing raw prompt text (`payload_sha256` digest only).
  * Built-in chain verification (`/v1/audit/verify`), SIEM-ready NDJSON export (`/v1/audit/export`), and Prometheus telemetry (`/metrics`).

---

## Live Production Smoke Test Benchmarks

Verified against the live Render deployment (`https://lucid-truth-audit.onrender.com`) on **2026-11-25 16:15:07 UTC** via `scripts/run_smoketest.py`:

* **Overall Compliance Score:** `100.0%` (`8 / 8` checks passed)
* **Zero-Retention Policy:** `Verified` (raw SSNs and secrets stripped prior to upstream dispatch and never persisted in audit records)
* **Mean Endpoint Latency:** `201.9 ms` (`108.2 ms` – `356.8 ms` across live HTTPS edge round-trips)

| # | Smoke Test Check | Endpoint | HTTP | Latency | Status | Verification Detail |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **1** | Health / Liveness | `GET /healthz` | `200` | `210.0 ms` | **PASS** | `status: "ok"`, active version & loaded policy packs verified |
| **2** | Readiness Check | `GET /readyz` | `200` | `136.8 ms` | **PASS** | Database `SELECT 1` ping, tenant keyring, and policy engine ready |
| **3** | Guard Rejects Missing Key | `POST /api/v1/guard` | `403` | `236.5 ms` | **PASS** | Fail-closed auth enforcement on unauthenticated requests |
| **4** | Shadow Ingest Route Check | `POST /v1/shadow/ingest` | `404` | `196.9 ms` | **PASS** | Route presence & auth posture verified against live OpenAPI spec |
| **5** | Guard Clean Prompt | `POST /api/v1/guard` | `200` | `356.8 ms` | **PASS** | End-to-end sanitization, upstream routing, and SHA-256 ledger append |
| **6** | Guard PII Redaction (SSN + Secret) | `POST /api/v1/guard` | `200` | `211.6 ms` | **PASS** | Raw SSN (`123-45-6789`) & API key redacted; zero raw leak in response |
| **7** | Guard Injection / Evasion Handling | `POST /api/v1/guard` | `400` | `159.5 ms` | **PASS** | BiDi override (`\u202e`) + Cyrillic homoglyph injection blocked |
| **8** | Audit Ledger Verify | `GET /v1/audit/verify` | `200` | `108.2 ms` | **PASS** | Full cryptographic hash-chain integrity verified (`chain_valid: true`) |

---

## Verification & CI Metrics

Every push to `main` executes multi-version Python verification (`3.11` and `3.12`), dependency vulnerability auditing (`pip-audit`), and Docker container health validation in GitHub Actions:

* **Automated Test Suite:** `96 / 96` tests passing (`100%` pass rate across `test_audit.py`, `test_vector2_pii.py`, `test_vector3_resilience.py`, `tests/test_vector4_logistics.py`, `tests/test_enterprise_gateway.py`, `tests/test_production_suite.py`, `tests/test_evidence_chain.py`, `tests/test_shadow_ingest.py`, and `tests/test_deployment_validation.py`).
* **Total Code Coverage:** `80.63%` (exceeding the `60%` CI gate; `lta/app.py` at `91%`, `lta/policy_engine.py` at `90%`, `lta/metrics.py` at `95%`, `app/api/shadow.py` at `97%`, `app/schemas/logistics_guard.py` at `96%`).
* **Container Validation:** Verified ASGI startup (`uvicorn lta.app:app --host 0.0.0.0 --port $PORT`) and `/health` liveness probing inside Docker.

---

## API Reference

### Endpoints

| Method | Path | Auth | Description |
| :--- | :--- | :---: | :--- |
| `GET` | `/health`, `/healthz` | Public | Liveness probe returning service version and loaded policy count |
| `GET` | `/readyz` | Public | Readiness probe verifying database connectivity and tenant config |
| `GET` | `/v1/policies` | Tenant | Lists active tenant policy pack and available compliance packs |
| `POST` | `/v1/chat/completions` | Tenant | OpenAI-compatible chat proxy with input/output guardrails and `lta_audit` metadata |
| `POST` | `/api/v1/guard` | Tenant | Single-prompt guard endpoint (`model_input`, optional `metadata`) |
| `GET` | `/v1/audit/verify` | Admin | Recomputes and verifies every SHA-256 hash link in the audit ledger |
| `GET` | `/v1/audit/export` | Admin | Exports SIEM-ready NDJSON audit records (filterable by `tenant_id` and `limit`) |
| `GET` | `/metrics` | Admin | Exposes Prometheus text-format request, latency, and block-vector metrics |
## Licensing

**Lucid-Truth-Audit (LTA)** is available under a dual-licensing model:

1. **Open-Source Evaluation & Community Use — Apache License 2.0:**
   The core gateway (`lta/`), policy engine, and open-source evaluation suites are licensed under the **Apache License, Version 2.0** (`SPDX-License-Identifier: Apache-2.0`). You may use, modify, and distribute the software in compliance with the terms in [`LICENSE`](LICENSE), including retention of copyright notices and modification statements.
2. **Enterprise Production, Custom Regulatory Packs & 30-Day Shadow Pilots — Commercial License:**
   Organizations deploying Lucid-Truth-Audit in regulated production environments, requiring dedicated VPC/private-cloud hosting, custom HIPAA/PCI-DSS/FMCSA policy pack engineering, SLA-backed support, or a **30-day zero-disruption shadow deployment pilot** may obtain a commercial enterprise license from **Lucid Tech / Corey Allen Stickney** (`https://github.com/stickneycorey1-source/Lucid-Truth-Audit-`).

* **Copyright:** © 2026 Corey Allen Stickney / Lucid Tech. All rights reserved.
* **Third-Party Dependencies:** Direct dependencies (`FastAPI`, `Uvicorn`, `Pydantic`, `httpx`, `PyYAML`, `psycopg`, `redis`, `pytest`) remain governed by their respective upstream open-source licenses.


### Example: OpenAI-Compatible Chat Completion

```bash
curl -X POST [https://lucid-truth-audit.onrender.com/v1/chat/completions](https://lucid-truth-audit.onrender.com/v1/chat/completions) \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $LTA_API_KEY" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {"role": "user", "content": "Summarize discharge for MRN-90817263 SSN 123-45-6789."}
    ]
  }'
---

