# Lucid-Truth-Audit

[![CI — Pytest & Branch Coverage](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci_pytest.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci_pytest.yml)
[![Live Render Smoke Test](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/smoketest.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/smoketest.yml)
[![Python 3.11 & 3.12](https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2-E92063.svg)](https://docs.pydantic.dev/)
[![Pytest Branch Coverage](https://img.shields.io/badge/coverage-branch--enabled-22C55E.svg)](#complete-test--smoke-test-results)
[![Render Deployment](https://img.shields.io/badge/Render-Live%20API-46E3B7.svg)](https://lucid-truth-audit.onrender.com)
[![Privacy: Zero-Retention](https://img.shields.io/badge/Privacy-Zero--Retention-10B981.svg)](#security--privacy-architecture)
[![Audit Ledger: SHA-256 Chain](https://img.shields.io/badge/Audit%20Ledger-SHA--256%20Hash--Chain-6366F1.svg)](#evidence-chain--audit-ledger)
[![Security: BiDi & Homoglyph Hardened](https://img.shields.io/badge/Security-BiDi%20%26%20Homoglyph%20Hardened-F59E0B.svg)](#security--privacy-architecture)
[![Status: 9/9 Live Smoke Passed](https://img.shields.io/badge/Live%20Smoke-9%2F9%20Passed%20(100%25)-34D399.svg)](#complete-test--smoke-test-results)
[![Tests: 303/303 Passing](https://img.shields.io/badge/Unit%20%26%20Hardening-303%2F303%20Passed-16A34A.svg)](#complete-test--smoke-test-results)

Enterprise AI governance and prompt guardrail microservice engineered by **Lucid Tech**. Built on **Python 3.11 / 3.12**, **FastAPI**, and **Pydantic v2**, `Lucid-Truth-Audit` provides deterministic schema validation, Unicode NFKC normalization, PII/secret redaction, prompt-injection and evasion defense, zero-retention privacy guarantees, and tamper-evident SHA-256 hash-chained audit verification.

- **Production Base URL:** `https://lucid-truth-audit.onrender.com`
- **Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit-`
- **Local / CI Runtime:** Python `3.11.18` (local/CI) and `3.12` (CI & Live Smoke Test)

---

## Milestones & Engineering Roadmap

- **Milestone 1 — Core Guard Gateway & Shadow Ingest:**
  - Implemented `POST /api/v1/guard` (`X-API-Key`) for structured `model_input` validation, PII/secret redaction, and prompt-injection/evasion evaluation.
  - Implemented `POST /v1/shadow/ingest` (`Authorization: Bearer <shadow_key>`) to ingest shadow payloads—including bidirectional (`BiDi`) text and Unicode homoglyph evasion vectors—and return `202 Accepted` with an `audit_id` and SHA-256 reference hash.
  - Added liveness (`GET /healthz`), readiness (`GET /readyz`), and audit verification (`GET /v1/audit/verify`) endpoints.
- **Milestone 2 — Tenant-Isolated Cryptographic Ledger (`EvidenceChainStore`):**
  - Engineered SQLite persistence configured with `WAL` journal mode, `FULL` synchronous mode, and `BEGIN IMMEDIATE` write serialization to prevent write contention and race conditions.
  - Implemented canonical JSON hashing and SHA-256 hash-chaining seeded from `"GENESIS"`, computing each `entry_hash` across `schema_version`, `evidence_id`, `tenant_id`, `created_at`, `payload_json`, and `prev_hash`.
  - Enforced strict per-tenant isolation, `DuplicateEvidenceError` handling, non-finite number (`NaN`, `Infinity`, `-Infinity`) and blank-tenant rejection, and constant-time `hmac.compare_digest` verification returning `chain_valid` and `broken_at_record`.
- **Milestone 3 — Hardening & CI/CD Pipeline (`ci_pytest.yml`):**
  - Expanded the test suite to **303/303** passing tests locally, including dedicated hardening suites (`test_main_hardening.py`, `test_normalizer_hardening.py`, `test_ledger_hardening.py`, `test_evidence_chain_hardening.py`, `test_shadow_hardening.py`, and `test_logistics_guard_hardening.py`).
  - Fixed CI file discovery with `[ -f "$f" ]` existence guards and configured matrix execution across Python `3.11` and `3.12` with `--cov=app --cov-branch` and `coverage-<version>.xml` artifact uploads (`coverage-3.12.xml`, Artifact ID `15257004565`, SHA-256 `87c1b3e52ced401ce8e4ac3a7a34b5131017ea1a299529dad0cc0e18cf0dacba`).
- **Milestone 4 — Live Render Smoke Verification (`smoketest.yml`):**
  - Diagnosed and resolved schema mismatches on `POST /api/v1/guard` (`model_input` payload alignment and auto-detection) and added cold-start retry/backoff handling (`502`/`503`/`504` and `RequestException`) in `scripts/run_smoketest.py`.
  - Achieved **9/9 (`100.0%`)** passing smoke tests on `https://lucid-truth-audit.onrender.com` (`2026-11-28 11:46:43 UTC`) with HTML report artifact generation (`lucid-truth-audit-smoketest-report`).
- **Milestone 5 — Stakeholder Readiness & Pilot Rollout:**
  - Verified live service health, authentication boundaries, redaction behavior, and ledger integrity ahead of stakeholder discussions with **Muhammad Hassan (VantX)** on **November 28, 2026**.
  - Prepared zero-retention telemetry and shadow-ingest readiness ahead of the Zoom meeting and 30-day shadow pilot kickoff with **Amber Phillips (P2 Transportation Solutions)** on **November 30, 2026**.

---

## Core Capabilities & Architecture

- **Enterprise Guard Gateway (`/api/v1/guard`):** Authenticates callers via `X-API-Key`, validates `model_input` requests against strict Pydantic v2 schemas, redacts sensitive tokens/identifiers (such as SSNs and secret keys), and handles prompt-injection and evasion payloads.
- **Shadow Telemetry & Evasion Ingest (`/v1/shadow/ingest`):** Enforces bearer token authentication and ingests shadow telemetry—including BiDi overrides and homoglyph characters—returning `202 Accepted` with `audit_id` and SHA-256 hash tracking.
- **Cryptographic Evidence Chain (`EvidenceChainStore`):** Provides tenant-isolated append-only audit trails in SQLite (`WAL` + `FULL` + `BEGIN IMMEDIATE`), canonical payload hashing, SHA-256 chain linkage (`"GENESIS"` → `prev_hash` → `entry_hash`), and tamper detection via `verify(tenant_id)`.
- **Deterministic Normalization & Validation:** Normalizes Unicode inputs deterministically and rejects malformed types, non-finite floats, and blank tenant identifiers before persistence.

---

## Security & Privacy Architecture

- **Zero-Retention Policy:** Prompts and shadow payloads are processed with zero-retention privacy guarantees so sensitive data is not persisted in unhashed logs or retained beyond audit requirements.
- **Hash-Chain Integrity & Tamper Detection:** Every record links `prev_hash` to the prior tenant record's `entry_hash` (or `"GENESIS"` for the first entry). Any row alteration or chain break is detected by `verify(tenant_id)` (`chain_valid: False`, `broken_at_record`).
- **Authentication & Access Control:** Missing or invalid credentials on `/api/v1/guard` (`403`) and `/v1/shadow/ingest` (`401`) are rejected prior to payload processing.

---

## Endpoints & Verification Matrix

| Endpoint / Component | Purpose | Auth / Guard | Verified Live Status |
| :--- | :--- | :--- | :--- |
| `GET /healthz` | Service liveness check | Public | `200 OK` |
| `GET /readyz` | Service readiness check | Public | `200 OK` |
| `POST /api/v1/guard` | Clean prompt check, PII/secret redaction, injection/evasion handling | `X-API-Key` | `403` (missing key), `200` / `400` / `403` (keyed) |
| `POST /v1/shadow/ingest` | Shadow ingest for BiDi & homoglyph payloads | `Bearer` token | `401` (missing token), `202 Accepted` (keyed) |
| `GET /v1/audit/verify` | Audit ledger integrity verification | `X-API-Key` | `200 OK` |
| `EvidenceChainStore` | Tenant-isolated SHA-256 hash chain (`add`, `list_records`, `verify`) | Internal / SQLite WAL | Verified across unit & concurrency tests |

---

## Quick Start & Local Testing

### 1. Environment Setup

```bash
git clone [https://github.com/stickneycorey1-source/Lucid-Truth-Audit-.git](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-.git)
cd Lucid-Truth-Audit-

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
pip install pytest pytest-cov httpx requests

2. Run Hardening & Branch Coverage Suite
export LUCID_AUDIT_API_KEY="ci-ephemeral-guard-key"
export LTA_TENANT_KEYS='{"ci_tenant":"ci-ephemeral-shadow-key"}'
export LUCID_LEDGER_DB_PATH=":memory:"

mkdir -p reports
pytest --cov=app --cov-branch --cov-report=term-missing --cov-report=xml:coverage.xml -vv

3. Run Live Render Smoke Test Locally
export LTA_BASE_URL="[https://lucid-truth-audit.onrender.com](https://lucid-truth-audit.onrender.com)"
export LTA_API_KEY="your-guard-api-key"
export LTA_SHADOW_KEY="your-shadow-bearer-key"
export LTA_TIMEOUT_SECONDS="30"
export LTA_REPORT_PATH="lta_smoketest_report.html"

python scripts/run_smoketest.py

GitHub Actions Workflows & Secrets
 * CI Workflow (.github/workflows/ci_pytest.yml): Executes pytest --cov=app --cov-branch across Python 3.11 and 3.12 on pushes and pull requests targeting main, safely checking hardening test files with [ -f "$f" ] and uploading coverage-<version>.xml (coverage-3.12.xml, 3,998 bytes).
 * Smoke Test Workflow (.github/workflows/smoketest.yml): Manual workflow_dispatch workflow against https://lucid-truth-audit.onrender.com (with base_url and timeout_seconds inputs), running python scripts/run_smoketest.py and uploading lta_smoketest_report.html under lucid-truth-audit-smoketest-report.
 * Required Repository Secrets: Set LTA_API_KEY and LTA_SHADOW_KEY in Settings → Secrets and variables → Actions.
Complete Test & Smoke Test Results
1. Unit, Hardening & CI Suite Summary
 * Hardening & Full Test Suite: 303/303 tests passing locally; CI executes across Python 3.11 and 3.12 with branch coverage enabled (--cov=app --cov-branch).
 * Coverage Artifact Uploaded: coverage-3.12.xml (3,998 bytes, Artifact ID 15257004565, SHA-256 87c1b3e52ced401ce8e4ac3a7a34b5131017ea1a299529dad0cc0e18cf0dacba).
 * Hardening Test Modules: tests/test_main_hardening.py, tests/test_normalizer_hardening.py, tests/test_ledger_hardening.py, tests/test_evidence_chain_hardening.py, tests/test_shadow_hardening.py, and tests/test_logistics_guard_hardening.py.
2. Live Render Smoke Test Results (2026-11-28 11:46:43 UTC — 9/9 Passed · 100.0%)
Target: https://lucid-truth-audit.onrender.com · Latest SHA-256 Reference: 5c303fae2ce8e0c4e581e09f3d1445a3e6a67f77ad4d473d94df6efc10dc580d
| # | Check | Endpoint | HTTP | Latency | Status | Detail |
|---|---|---|---|---|---|---|
| 1 | Health (/healthz) | /healthz | 200 | 262.3 ms | PASS | OK |
| 2 | Readiness (/readyz) | /readyz | 200 | 134.3 ms | PASS | OK |
| 3 | Guard Missing Key | /api/v1/guard | 403 | 240.2 ms | PASS | HTTP 403 |
| 4 | Shadow Missing Key | /v1/shadow/ingest | 401 | 136.8 ms | PASS | HTTP 401 |
| 5 | Guard Clean Prompt | /api/v1/guard | 200 | 1122.4 ms | PASS | OK (field=model_input) |
| 6 | Guard PII Redaction | /api/v1/guard | 200 | 311.0 ms | PASS | Redacted |
| 7 | Guard Injection | /api/v1/guard | 400 | 139.3 ms | PASS | status=handled |
| 8 | Audit Verify | /v1/audit/verify | 200 | 243.8 ms | PASS | OK |
| 9 | Shadow Ingest | /v1/shadow/ingest | 202 | 119.7 ms | PASS | audit_id=lta-shadow-4-f57c3ceaa215 |

## Environment Variables & Configuration Reference

- **Guard & Shadow Authentication:**
  - `LUCID_AUDIT_API_KEY`: API key required for `/api/v1/guard` and `/v1/audit/verify` requests (`X-API-Key`).
  - `LTA_TENANT_KEYS`: JSON mapping of tenant identifiers to shadow bearer credentials for `/v1/shadow/ingest`.
  - `LTA_API_KEY` & `LTA_SHADOW_KEY`: GitHub Actions secrets and smoke-test runner environment variables used against live deployments.
- **Ledger & Runtime Configuration:**
  - `LUCID_LEDGER_DB_PATH`: Path to the SQLite ledger database (`:memory:` for isolated test runs or a persistent file path for local/production deployments).
  - `LTA_BASE_URL`: Target service base URL for `scripts/run_smoketest.py` (defaults to `https://lucid-truth-audit.onrender.com`).
  - `LTA_TIMEOUT_SECONDS`: Per-request HTTP timeout in seconds for live smoke checks (defaults to `15`; increase to `30`–`45` when waking a sleeping Render instance).
  - `LTA_REPORT_PATH`: Output path for the HTML smoke report (`lta_smoketest_report.html`).
  - `LTA_GUARD_FIELD`: Optional override for the guard request payload field name (`model_input` by default, with fallback probing across `prompt`, `text`, `content`, `input`, and `messages`).

---

## Repository Structure

```text
Lucid-Truth-Audit-/
├── .github/
│   └── workflows/
│       ├── ci_pytest.yml              # Pytest + branch coverage matrix (Python 3.11 & 3.12)
│       └── smoketest.yml              # Manual workflow_dispatch live Render smoke test
├── app/
│   └── evidence_chain.py              # Tenant-isolated SQLite WAL SHA-256 hash-chain ledger
├── lta/
│   └── app.py                         # FastAPI enterprise audit & guard gateway
├── scripts/
│   └── run_smoketest.py               # Live smoke test runner + Chart.js HTML report generator
└── tests/
    ├── test_main_hardening.py         # Gateway & API hardening tests
    ├── test_normalizer_hardening.py   # Deterministic normalization & Unicode hardening tests
    ├── test_ledger_hardening.py       # Ledger persistence & integrity tests
    ├── test_evidence_chain_hardening.py # Hash-chain, concurrency & tamper-detection tests
    ├── test_shadow_hardening.py       # Shadow ingest, BiDi & homoglyph hardening tests
    └── test_logistics_guard_hardening.py # Logistics / domain guardrail hardening tests


