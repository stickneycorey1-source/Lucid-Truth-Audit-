# Lucid-Truth-Audit (LTA) · Enterprise AI Security & Compliance Gateway

[![Test Suite](https://img.shields.io/badge/tests-96%2F96%20passing-brightgreen.svg)](#verification--ci-metrics)
[![Code Coverage](https://img.shields.io/badge/coverage-80.63%25-brightgreen.svg)](#verification--ci-metrics)
[![Live Smoke Test](https://img.shields.io/badge/live%20smoke%20test-100%25%20(8%2F8)-brightgreen.svg)](#live-production-smoke-test-benchmarks)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.165%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063.svg)](https://docs.pydantic.dev/)
[![Zero-Retention](https://img.shields.io/badge/zero--retention-verified-success.svg)](#cryptographic-audit-ledger--zero-retention)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%7C%20Commercial-blue.svg)](#licensing)

**Lucid-Truth-Audit (LTA)** is a hardened, drop-in OpenAI-compatible AI security, PII/PHI redaction, and regulatory compliance gateway (`v2.4.1`). Positioned in front of upstream foundation models (`OpenAI`, `Azure OpenAI`, `Anthropic`, `Google Gemini`, `vLLM`, `Ollama`, or simulated fallback), it enforces input normalization, prompt-injection and multi-turn role defenses, domain policy packs, output boundary checks, and SHA-256 hash-chained audit logging with zero raw-prompt retention.

* **Live Deployment:** `https://lucid-truth-audit.onrender.com`[span_0](start_span)[span_0](end_span)[span_1](start_span)[span_1](end_span)
* **Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit-`

---

## Core Capabilities

* **OpenAI-Compatible & Legacy Guard Endpoints:** Serves `POST /v1/chat/completions` (`object: "chat.completion"`, `choices`, and `lta_audit` metadata) alongside `POST /api/v1/guard` (`status`, `allowed`, and pipeline audit fields).
* **Input Normalization & Threat Defense:**
  * NFKC Unicode normalization, zero-width/BiDi override stripping (`\u202e`), Cyrillic/homoglyph detection, and Base64/Hex/leetspeak payload inspection.
  * Multi-turn conversation scanning to block cross-turn split injections, unauthorized `system` role spoofing after index `0` or by non-admin callers (`security.multi_turn_system_spoofing`), and poisoned `assistant` history turns.
  * High-entropy gibberish, repeating-character, and repeating-word flood detection.
* **Domain Regulatory Policy Packs:**
  * **Healthcare (`healthcare_hipaa`):** Redacts Medical Record Numbers (`MRN`), SSNs, and sensitive identifiers while enforcing clinical data boundaries.
  * **Finance (`finance_pci`):** Luhn-validated PAN card redaction with benign ID preservation and wire-threshold metadata evaluation (`wire_amount_usd`).
  * **Logistics (`logistics_fmcsa`):** Multi-state `CDL`/`DL` redaction with `PO` preservation, 60/7 and 70/8 Hours-of-Service (`HOS`) and gross-weight validation, and BOL prompt-injection / waypoint-hijack protection.
  * **General Enterprise (`general_enterprise`):** Baseline PII redaction, social-engineering pretext blocking, and output secret/instruction boundary protection.
* **Authentication, RBAC & Resilience:**
  * Fail-closed authentication (`X-API-Key` or `Authorization: Bearer`) rejecting missing/invalid keys (`403`) or unconfigured tenant keyrings (`500`).
  * Admin role enforcement (`403` for non-admin `X-LTA-Policy` / `X-LTA-Provider` overrides or access to `/v1/audit/verify`, `/v1/audit/export`, and `/metrics`).
  * Per-tenant sliding-window rate limiting (`429` with `X-RateLimit-Remaining`), strict Pydantic v2 validation (`extra="forbid"`, `NaN`/non-numeric metadata rejection), and `256 KiB` (`LTA_MAX_BODY_BYTES`) streaming body limits (`413`).
* **Cryptographic Audit Ledger & Zero-Retention:**
  * Append-only SQLite and PostgreSQL (`pg_advisory_xact_lock`) audit log chaining events via SHA-256 (`prev_hash` -> `entry_hash`) and storing `payload_sha256` digests rather than raw prompt text.

---

## Live Production Smoke Test Benchmarks

Verified against `https://lucid-truth-audit.onrender.com` on **2026-11-25 16:15:07 UTC** via `scripts/run_smoketest.py`:

* **Compliance Score:** `100.0%` (`8 / 8` checks passed)
* **Zero-Retention Policy:** `Verified`
* **Mean Latency Across All 8 Checks:** `201.9 ms` (`108.2 ms` minimum to `356.8 ms` maximum)[span_2](start_span)[span_2](end_span)[span_3](start_span)[span_3](end_span)

| # | Smoke Test Check | Endpoint | HTTP | Latency | Status | Detail |
| :-: | :--- | :--- | :---: | :---: | :---: | :--- |
| **1** | Health / Liveness | `/healthz` | `200` | `210.0 ms` | **PASS** | OK |
| **2** | Readiness Check | `/readyz` | `200` | `136.8 ms` | **PASS** | OK |
| **3** | Guard Rejects Missing Key | `/api/v1/guard` | `403` | `236.5 ms` | **PASS** | OK |
| **4** | Shadow Ingest | `/v1/shadow/ingest` | `404` | `196.9 ms` | **PASS** | Not yet mounted on Render (404) |
| **5** | Guard Clean Prompt | `/api/v1/guard` | `200` | `356.8 ms` | **PASS** | OK |
| **6** | Guard PII Redaction (SSN + Secret) | `/api/v1/guard` | `200` | `211.6 ms` | **PASS** | Raw SSN not leaked in response |
| **7** | Guard Injection / Evasion Handling | `/api/v1/guard` | `400` | `159.5 ms` | **PASS** | `status=handled` |
| **8** | Audit Ledger Verify | `/v1/audit/verify` | `200` | `108.2 ms` | **PASS** | OK[span_4](start_span)[span_4](end_span)[span_5](start_span)[span_5](end_span) |

---

## Verification & CI Metrics

GitHub Actions runs automated verification across Python `3.11` and `3.12`, dependency vulnerability auditing (`pip-audit`), and Docker container health checks:

* **Test Suite Pass Rate:** `96 / 96` tests passing (`100%`) across unit, policy, resilience, logistics, shadow ingest, evidence chain, deployment validation, and enterprise gateway suites.
* **Total Code Coverage:** `80.63%` (above the `60%` CI requirement; `lta/app.py` at `91%`, `lta/policy_engine.py` at `90%`, `lta/metrics.py` at `95%`, `app/api/shadow.py` at `97%`, `app/schemas/logistics_guard.py` at `96%`).
* **Container Validation:** Verified `docker-compose.yml` syntax, Docker image build, ASGI startup (`uvicorn lta.app:app --host 0.0.0.0 --port $PORT`), and `/health` liveness probing.

---

## Project Milestones

* **Milestone 1 — Core Guardrail & Policy Engine Foundation:** Implemented NFKC normalization, obfuscation/homoglyph/encoding detection, multi-turn injection & role defenses, output boundary checks, and domain policy packs (`healthcare_hipaa`, `finance_pci`, `logistics_fmcsa`, `general_enterprise`).
* **Milestone 2 — SHA-256 Hash-Chained Audit Ledger:** Built tamper-evident append-only audit logging with `GENESIS_HASH`, `payload_sha256`, `prev_hash` -> `entry_hash` chaining, chain verification (`/v1/audit/verify`), and NDJSON export (`/v1/audit/export`) with zero raw-prompt retention.
* **Milestone 3 — ASGI Export & Gateway Response Schema Alignment:** Fixed module-level `app` export in `lta/app.py` for `uvicorn lta.app:app` container startup and aligned `/v1/chat/completions` and `/api/v1/guard` payloads (`object: "chat.completion"`, `choices`, `lta_audit.entry_hash`, `status: "success"`) to reach `96/96` passing CI tests and `80.63%` coverage.
* **Milestone 4 — Live Render Deployment & 100% Smoke Verification:** Deployed `lta/app.py` and `lta/providers.py` (with opt-in `LTA_ALLOW_SIMULATED_FALLBACK` and secret-scrubbed upstream error handling) to `https://lucid-truth-audit.onrender.com`, achieving `8/8` (`100.0%`) passing live smoke tests on `2026-11-25`[span_6](start_span)[span_6](end_span)[span_7](start_span)[span_7](end_span).
* **Milestone 5 — Enterprise Documentation & 30-Day Shadow Pilot Readiness:** Authored `README.md`, `LICENSE`, `SECURITY.md`, and `docs/` (`ARCHITECTURE.md`, `API_REFERENCE.md`, `POLICY_PACKS.md`, `DEPLOYMENT_AND_CI.md`, `SHADOW_PILOT_RUNBOOK.md`) to support B2B 30-day zero-disruption shadow deployment pilots.

---

## Documentation & Runbooks

* **[System Architecture](docs/ARCHITECTURE.md):** Request pipeline, module responsibilities, and response contract.
* **[API Reference](docs/API_REFERENCE.md):** Endpoints, authentication headers, RBAC controls, and schemas.
* **[Policy Packs & Threat Vectors](docs/POLICY_PACKS.md):** HIPAA, PCI-DSS, FMCSA, and General Enterprise rules and detection vectors.
* **[Deployment & Production CI Guide](docs/DEPLOYMENT_AND_CI.md):** GitHub Actions jobs, Render configuration, and smoke test workflow.
* **[30-Day Shadow Deployment Pilot Runbook](docs/SHADOW_PILOT_RUNBOOK.md):** Enterprise onboarding, SIEM export, and production cutover steps.
* **[Security Policy](SECURITY.md):** Zero-retention guarantees, cryptographic chain integrity, and vulnerability reporting.

---

## Quickstart & Local Usage

### Run Locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export LUCID_TENANT_KEYS="dev-admin:admin-key-123:general_enterprise:mock:admin"
uvicorn lta.app:app --host 0.0.0.0 --port 10000

Run Pytest Suite with Coverage
mkdir -p reports
python -m pytest -o addopts="" -v \
  --cov=app --cov=lta \
  --cov-report=term-missing \
  --cov-report=html:reports/coverage \
  --cov-fail-under=60 \
  --html=reports/compliance_audit.html \
  --self-contained-html \
  --json-report \
  --json-report-file=reports/audit_ledger.json

Run Live Smoke Test
export LTA_BASE_URL="[https://lucid-truth-audit.onrender.com](https://lucid-truth-audit.onrender.com)"
export LTA_API_KEY="<your-tenant-or-admin-key>"
python scripts/run_smoketest.py

Configuration Reference
| Variable | Default | Description |
|---|---|---|
| LUCID_TENANT_KEYS | (required) | Tenant definitions (tenant_id:api_key:policy_pack:provider:role) |
| LTA_POLICY_DIR | policies | Directory containing YAML policy packs |
| LTA_AUDIT_DB_URL | sqlite:///./lta_audit_ledger.db | SQLite file path or PostgreSQL connection URI |
| LTA_REDIS_URL | None | Optional Redis URL for distributed sliding-window rate limiting |
| LTA_REDIS_FAIL_MODE | memory | Rate-limiter fallback when Redis is unavailable (memory or closed) |
| LTA_MAX_BODY_BYTES | 262144 (256 KiB) | Max request payload size (413 when exceeded) |
| LTA_UPSTREAM_TIMEOUT_S | 30.0 | Timeout in seconds for upstream LLM requests |
| LTA_ALLOW_SIMULATED_FALLBACK | false | Enables simulated upstream fallback when provider keys are unset (smoke/staging) |
| LTA_DISABLE_DOCS | false | Disables /docs, /redoc, and /openapi.json when true |
Licensing
Lucid-Truth-Audit (LTA) uses a dual-licensing model:
 * Open-Source Evaluation & Community Use — Apache License 2.0: Licensed under the Apache License, Version 2.0 (SPDX-License-Identifier: Apache-2.0). See LICENSE for full terms and conditions.
 * Enterprise Production, Custom Packs & 30-Day Shadow Pilots — Commercial License: Commercial licensing, dedicated VPC/private-cloud deployments, custom regulatory policy packs, SLA support, and 30-day zero-disruption shadow deployment pilots are available from Lucid Tech / Corey Allen Stickney (https://github.com/stickneycorey1-source/Lucid-Truth-Audit-).
 * Copyright: © 2026 Corey Allen Stickney / Lucid Tech. All rights reserved.

