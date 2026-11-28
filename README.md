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

Enterprise AI governance and prompt guardrail microservice engineered by **Lucid Tech**. Built on **Python 3.11 / 3.12**, **FastAPI**, and **Pydantic v2**, `Lucid-Truth-Audit` provides deterministic schema validation, Unicode NFKC normalization, PII/secret redaction, prompt-injection & evasion defense, zero-retention privacy guarantees, and tamper-evident SHA-256 hash-chained audit verification.

- **Production Base URL:** `https://lucid-truth-audit.onrender.com`
- **Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit-`
- **Local / CI Runtime:** Python `3.11.18` (local/CI) and `3.12` (CI & Live Smoke Test)

---

## Milestones & Roadmap

- **Milestone 1 — Core Guard Gateway & Shadow Ingest:** Implemented `/api/v1/guard` (`X-API-Key`) and `/v1/shadow/ingest` (`Bearer` auth) for prompt governance, PII/secret redaction, injection/evasion handling, and bidirectional (`BiDi`) / Unicode homoglyph shadow ingestion.
- **Milestone 2 — Tenant-Isolated Cryptographic Ledger (`EvidenceChainStore`):** Built SQLite ledger (`WAL` mode, `FULL` synchronous mode, `BEGIN IMMEDIATE` write serialization) with canonical JSON and SHA-256 hash-chaining from `"GENESIS"`, per-tenant isolation, concurrent write protection, `DuplicateEvidenceError` handling, and `hmac.compare_digest` verification.
- **Milestone 3 — Hardening & CI/CD Pipeline (`ci_pytest.yml`):** Expanded test coverage to `303/303` passing tests including dedicated hardening suites (`test_evidence_chain_hardening.py`, `test_main_hardening.py`, `test_normalizer_hardening.py`, `test_ledger_hardening.py`, `test_shadow_hardening.py`, `test_logistics_guard_hardening.py`), safe `[ -f "$f" ]` file discovery across Python `3.11` and `3.12`, and `coverage-3.12.xml` artifact uploads.
- **Milestone 4 — Live Render Smoke Verification (`smoketest.yml`):** Resolved `/api/v1/guard` `model_input` payload alignment and Render cold-start retry/timeout handling, achieving **9/9 (`100.0%`)** live smoke test pass rate on `https://lucid-truth-audit.onrender.com` (`2026-11-28 11:46:43 UTC`).
- **Milestone 5 — Stakeholder Readiness & Pilot Rollout:** Verified live deployment readiness ahead of investor discussions with **Muhammad Hassan (VantX)** on **November 28, 2026** and Zoom kickoff + 30-day zero-retention shadow pilot coordination with **Amber Phillips (P2 Transportation Solutions)** on **November 30, 2026**.

---

## Core Capabilities

- **Enterprise Guard Gateway (`/api/v1/guard`):** Authenticates requests via `X-API-Key`, validates structured `model_input` payloads with strict schema enforcement, redacts sensitive identifiers (such as SSNs and API/secret tokens), and detects or blocks prompt injection and evasion attempts.
- **Shadow Telemetry & Evasion Ingest (`/v1/shadow/ingest`):** Enforces bearer authentication (`Authorization: Bearer <shadow_key>`) and ingests shadow payloads—including bidirectional (`BiDi`) text and Unicode homoglyph evasion vectors—returning `202 Accepted` with an `audit_id` and SHA-256 reference hash.
- **Cryptographic Evidence Chain (`EvidenceChainStore`):** Stores tenant-isolated records in SQLite (`WAL` journal mode, `FULL` synchronous mode, `BEGIN IMMEDIATE` write serialization) using canonical JSON serialization and SHA-256 hash-chaining linked to `"GENESIS"` and verified with constant-time `hmac.compare_digest` checks.
- **Deterministic Normalization & Hardening:** Normalizes text inputs deterministically, rejects non-finite numbers (`NaN`, `Infinity`, `-Infinity`) and blank tenant identifiers, and provides branch-covered `pytest` suites across Python 3.11 and 3.12.

---

## Security & Privacy Architecture

- **Zero-Retention Policy:** Sensitive inputs are evaluated and redacted without retaining raw PII in long-lived application logs or unhashed shadow records.
- **Canonical Hashing & Tamper Detection:** Each record in `EvidenceChainStore` computes a deterministic `entry_hash` over `schema_version`, `evidence_id`, `tenant_id`, `created_at`, `payload_json`, and `prev_hash`. Modifying any persisted row or breaking link continuity causes `verify(tenant_id)` to flag `chain_valid: False` at `broken_at_record`.
- **Auth Boundaries:** Unauthenticated requests to `/api/v1/guard` and `/v1/shadow/ingest` are rejected (`403` / `401`).

---

## Endpoints & Verification Matrix

| Endpoint / Component | Purpose | Auth / Guard | Verified Live Status |
| :--- | :--- | :--- | :--- |
| `GET /healthz` | Service liveness probe | Public | `200 OK` |
| `GET /readyz` | Service readiness probe | Public | `200 OK` |
| `POST /api/v1/guard` | Clean prompt evaluation, PII redaction, injection/evasion handling | `X-API-Key` | `403` (no key), `200` / `400` / `403` (keyed) |
| `POST /v1/shadow/ingest` | Shadow telemetry ingestion (BiDi & homoglyph payloads) | `Bearer` token | `401` (no token), `202 Accepted` (keyed) |
| `GET /v1/audit/verify` | Audit ledger integrity verification | `X-API-Key` | `200 OK` |
| `EvidenceChainStore` | Tenant-isolated SHA-256 hash chain (`add`, `list_records`, `verify`) | Internal / SQLite WAL | Verified in unit & concurrency tests |

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
 * CI Workflow (.github/workflows/ci_pytest.yml): Runs pytest with branch coverage (--cov=app --cov-branch) across Python 3.11 and 3.12 on pushes and pull requests to main, uploading coverage-<version>.xml artifacts (coverage-3.12.xml, 3,998 bytes).
 * Smoke Test Workflow (.github/workflows/smoketest.yml): Manual workflow_dispatch runner targeting https://lucid-truth-audit.onrender.com (configurable base_url and timeout_seconds), generating lta_smoketest_report.html and uploading the lucid-truth-audit-smoketest-report artifact.
 * Required Repository Secrets: Configure LTA_API_KEY and LTA_SHADOW_KEY under Settings → Secrets and variables → Actions.
Complete Test & Smoke Test Results
1. Unit, Hardening & CI Suite Summary
 * Hardening & Full Test Suite: 303/303 tests passing locally; ci_pytest.yml executes across Python 3.11 and 3.12 with --cov=app --cov-branch and uploads coverage-3.12.xml (Artifact ID 15257004565, SHA-256 87c1b3e52ced401ce8e4ac3a7a34b5131017ea1a299529dad0cc0e18cf0dacba).
 * Hardening Test Modules Covered in CI: tests/test_main_hardening.py, tests/test_normalizer_hardening.py, tests/test_ledger_hardening.py, tests/test_evidence_chain_hardening.py, tests/test_shadow_hardening.py, and tests/test_logistics_guard_hardening.py (with [ -f "$f" ] existence guards).
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

