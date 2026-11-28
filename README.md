# Lucid-Truth-Audit

[![CI — Pytest & Branch Coverage](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci_pytest.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci_pytest.yml)
[![Live Render Smoke Test](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/smoketest.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/smoketest.yml)
[![Python 3.11 & 3.12](https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2-E92063.svg)](https://docs.pydantic.dev/)
[![Render Deployment](https://img.shields.io/badge/Render-Live%20API-46E3B7.svg)](https://lucid-truth-audit.onrender.com)
[![Privacy: Zero-Retention](https://img.shields.io/badge/Privacy-Zero--Retention-10B981.svg)](#security--privacy-architecture)
[![Audit Ledger: SHA-256 Chain](https://img.shields.io/badge/Audit%20Ledger-SHA--256%20Hash--Chain-6366F1.svg)](#evidence-chain--audit-ledger)

Enterprise AI governance and prompt guardrail microservice engineered by **Lucid Tech**. Built on **Python 3.11 / 3.12**, **FastAPI**, and **Pydantic v2**, `Lucid-Truth-Audit` provides deterministic schema validation, Unicode NFKC normalization, PII/secret redaction, prompt-injection & evasion defense, zero-retention privacy guarantees, and tamper-evident SHA-256 hash-chained audit verification.

- **Production Base URL:** `https://lucid-truth-audit.onrender.com`
- **Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit-`
- **Local / CI Runtime:** Python `3.11.18` (local/CI) and `3.12` (CI & Live Smoke Test)

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
