# Lucid-Truth-Audit (`v2.0.3`)

[![Version](https://img.shields.io/badge/version-2.0.3-blue.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit)
[![Release Status](https://img.shields.io/badge/release-hardened%20production-2f855a.svg)](https://lucid-truth-audit.onrender.com/docs)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Pydantic](https://img.shields.io/badge/Pydantic-v2%20strict%20validation-E92063.svg)](https://docs.pydantic.dev/latest/)
[![Pytest](https://img.shields.io/badge/Pytest-63%20hardening%20tests-0A9EDC.svg)](#hardening-test-suites--validation-results)
[![Branch Coverage](https://img.shields.io/badge/branch%20coverage-95.23%25%20mean-2f855a.svg)](#hardening-test-suites--validation-results)
[![Storage](https://img.shields.io/badge/SQLite-WAL%20%7C%20BEGIN%20IMMEDIATE-003B57.svg)](#4-cryptographic-audit-ledger--evidence-chain-appledgerpy-appevidencechainpy)
[![Cryptography](https://img.shields.io/badge/Crypto-SHA--256%20%7C%20HMAC%20Constant--Time-1a365d.svg)](#4-cryptographic-audit-ledger--evidence-chain-appledgerpy-appevidencechainpy)
[![Privacy](https://img.shields.io/badge/Zero%20Retention-No%20Raw%20Prompt%20Store-9b2c2c.svg)](#zero-retention--privacy-architecture)
[![Compliance](https://img.shields.io/badge/FMCSA-49%20CFR%20%C2%A7%20395.3-2f855a.svg)](https://www.ecfr.gov/current/title-49/subtitle-B/chapter-III/subchapter-B/part-395/subpart-A/section-395.3)
[![Weight & Permits](https://img.shields.io/badge/Weight-80%2C000%20lb%20%2B%20XX--OSW--NNNN-2b6cb0.svg)](#5-fmcsa-fleet--logistics-guard-appschemaslogisticsguardpy)
[![CSV Security](https://img.shields.io/badge/CSV-Formula%20Injection%20Safe-d97706.svg)](#2-guard-pii-redaction--ingress-hardening-appmainpy)
[![Auth](https://img.shields.io/badge/Auth-API%20Key%20%7C%20Bearer%20Fail--Closed-4a5568.svg)](#authentication--fail-closed-controls)
[![Deployment](https://img.shields.io/badge/Render-Live%20API%20%26%20Docs-6b46c1.svg)](https://lucid-truth-audit.onrender.com/docs)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit)
[![Code Style](https://img.shields.io/badge/typing-PEP%20484%20%7C%20annotations-3776AB.svg)](#architecture--visuals)
[![License](https://img.shields.io/badge/License-Proprietary%20%28Lucid%20Tech%29-111827.svg)](#license)

**Lucid-Truth-Audit** is a deterministic AI security, zero-retention PII redaction, tamper-evident cryptographic audit ledger, and FMCSA 49 CFR § 395.3 fleet compliance microservice built with Python (`3.11` / `3.12`), FastAPI, Pydantic v2, and SQLite (`WAL` mode).

* **Live API & Swagger UI:** `https://lucid-truth-audit.onrender.com/docs`
* **GitHub Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit`
* **Built by:** Lucid Tech

---

## Table of Contents

1. [Architecture & Visuals](#architecture--visuals)
2. [Detailed Module & Security Specifications](#detailed-module--security-specifications)
3. [API Reference & Endpoints](#api-reference--endpoints)
4. [Configuration & Environment Variables](#configuration--environment-variables)
5. [Benchmarks & Performance Data](#benchmarks--performance-data)
6. [Hardening Test Suites & Validation Results](#hardening-test-suites--validation-results)
7. [Threat Audit Export Sanitization & Chain Verification](#threat-audit-export-sanitization--chain-verification)
8. [Quick Start, Smoke Tests & Deployment](#quick-start-smoke-tests--deployment)
9. [Pricing & Pilot Tiers](#pricing--pilot-tiers)
10. [Expert Review](#expert-review)
11. [License](#license)

---

## Architecture & Visuals

![Pipeline Latency and Hardening Test Coverage](lta_benchmarks_and_coverage.png)

![LTA Threat Audit Export — Verified Chain & Policy Actions](lta_verified_chain_summary.png)

### End-to-End Request & Audit Pipeline

```text
Incoming HTTP / API Request (Guard / Logistics Guard / Shadow Ingest / Evidence / Ledger)
       │
       ▼
[1. RequestBodyLimitMiddleware] ──▶ Enforces LUCID_MAX_BODY_BYTES (default 1 MiB)
       │                            Returns HTTP 413 with Cache-Control: no-store & nosniff
       ▼
[2. Authentication & Rate Gate] ──▶ Validates X-API-Key or Bearer token via SHA-256 + hmac.compare_digest
       │                            Fails closed (503 if unconfigured/malformed, 401 if invalid/missing)
       ▼
[3. Input Normalizer & Sanitizer]──▶ Strips BiDi overrides, zero-width/fillers, VS16, combining marks
       │                            NFKC + homoglyph + leet fold; decodes URL / Base64 / Hex
       ▼
[4. Policy, PII & HOS Guard]    ──▶ Blocks prompt injection, role spoofing, social engineering, floods
       │                            Redacts SSN, Luhn PAN, secrets, CDL/phone/email (preserves PO/TR)
       │                            Enforces 49 CFR § 395.3 HOS, 80k lb cap, XX-OSW-NNNN & waypoints
       ▼
[5. Zero-Retention / Ledger]    ──▶ Shadow mode: logs SHA-256 hashes & flags only (no raw/clean prompt)
                                    Ledger/Chain: BEGIN IMMEDIATE WAL + canonical JSON + SHA-256 chain

Detailed Module & Security Specifications
1. Multi-Layer Input Normalization & Unicode Defense (app/normalizer.py, app/core/sanitizer.py)
 * Bidirectional & Invisible Character Stripping: Removes BiDi override and isolate controls (U+061C, U+200E–U+200F, U+202A–U+202E, U+2066–U+2069), invisible smuggling characters (U+034F, U+115F, U+1160, U+3164, U+FFA0, U+FE00–U+FE0F), Cc control characters outside safe whitespace (\t, \n, \r), and Cf format characters.
 * Compatibility & Homoglyph Folding: Applies Unicode NFKC normalization, detects mixed-script vs. non-Latin confusables (CYRILLIC, GREEK), and folds Cyrillic/homoglyph/leetspeak substitutions (such as Cyrillic а U+0430 -> a) prior to policy inspection.
 * Encoded Payload Decoding: Decodes URL-percent encoding, standard/URL-safe/padded/unpadded Base64, and contiguous, 0x-prefixed, or space-delimited Hex payloads so hidden instructions cannot bypass pattern checks.
 * Deduplication & Bounded Inspection: Deduplicates normalized variants cleanly while preserving deterministic ordering and preventing unbounded expansion.
2. Guard, PII Redaction & Ingress Hardening (app/main.py)
 * Threat & Anomaly Detection: Evaluates normalized inputs for prompt injection, multi-turn role spoofing, social-engineering PII pretexts, excessive character repetition, and entropy anomalies.
 * Linear-Time PII & Secret Scrubbing: Redacts SSNs (hyphenated and space-delimited), Luhn-checked payment card PANs using a linear-time regex ((?<!\d)(?:\d[ -]?){12,18}\d(?!\d)), and modern API keys/tokens (sk-..., ghp_..., AKIA..., AIza...) at the ingest boundary.
 * Middleware & Transport Hardening: Attaches RequestBodyLimitMiddleware to reject oversized payloads with HTTP 413 Payload Too Large, sets defensive HTTP headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy: no-referrer, and route-aware Content-Security-Policy), sanitizes Content-Disposition filenames, and neutralizes CSV formula injection (=, +, -, @, \t, \r) on export.
3. Zero-Retention Shadow Mode (app/api/shadow.py)
 * Non-Blocking 202 Accepted Workflow: Accepts shadow telemetry via POST /v1/shadow/ingest and executes sanitization in a background worker so the async event loop remains responsive.
 * Strict Zero-Retention Guarantee: ZeroRetentionAuditRecord records audit_id, tenant_id, request_id, model_target, timestamp_utc, input_sha256, sanitized_sha256, input_length, was_modified, strip/homoglyph counters, risk_flags, processing_ms, and bounded metadata—never storing or logging raw prompts or sanitized payload text.
 * Authentication & Bounds: Enforces bounded metadata (<= 20 keys, key length 1..64, value length <= 256), returns 503 Service Unavailable when LTA_TENANT_KEYS is missing or invalid JSON/non-dict, and compares SHA-256 token digests using hmac.compare_digest across the full map.
4. Cryptographic Audit Ledger & Evidence Chain (app/ledger.py, app/evidence_chain.py)
 * Serialized WAL Writes: Opens SQLite connections with contextlib.closing(), PRAGMA busy_timeout=15000, PRAGMA journal_mode=WAL, and PRAGMA synchronous=FULL, wrapping mutations and DDL in BEGIN IMMEDIATE transactions with safe if conn.in_transaction: conn.execute("ROLLBACK") guards.
 * Collision-Free Canonical Hashing: Serializes audit envelopes with canonical JSON (sort_keys=True, separators=(",", ":"), allow_nan=False), preventing pipe-delimiter (|) concatenation collisions and rejecting NaN/Infinity floats.
 * Tenant Isolation & Tamper Verification: Maintains independent GENESIS hash chains per tenant_id in EvidenceChainStore, raises DuplicateEvidenceError on duplicate (tenant_id, evidence_id), and verifies prev_hash and entry_hash via hmac.compare_digest.
5. FMCSA Fleet & Logistics Guard (app/schemas/logistics_guard.py)
 * FMCSA 49 CFR § 395.3 Single-Shift & Cycle Rules: Enforces up to 11.0 hours driving, 14.0 hours consecutive duty window, 8.0 hours maximum continuous driving before a >= 30-minute rest break, continuous_drive_before_break_hours <= planned_drive_hours, planned_drive_hours <= on_duty_window_hours, and 60_7 (60h/7d) or 70_8 (70h/8d) cumulative cycle limits.
 * Weight, Oversize Permit & Geofence Checks: Enforces the 80,000 lb federal gross vehicle weight cap, requires a valid ^[A-Z]{2}-OSW-\d{4,10}$ oversize/overweight permit above 80,000 lbs, validates permit format whenever supplied (<= 80,000 lbs included), rejects NaN/Inf (allow_inf_nan=False), and blocks unauthorized waypoints (is_authorized_facility=False).
 * Indirect Injection & Context-Aware PII Scrubbing: Scans bill_of_lading_notes, dispatcher_summary, and waypoints[].label for normalized prompt injection, while redacting SSN, CDL, PHONE, and EMAIL (with fixed [A-Za-z]{2,} TLD matching) without corrupting operational PO, BOL, or TR identifiers.
API Reference & Endpoints
| Method | Endpoint | Auth | Status Codes | Description |
|---|---|---|---|---|
| GET | /health | Public | 200 | O(1) health probe returning status, ledger record count, and latest hash prefix |
| POST | /api/v1/guard | X-API-Key | 200, 401, 413, 422 | Prompt injection, anomaly detection, and zero-retention PII redaction |
| POST | /api/v1/guard/logistics | X-API-Key | 200, 401, 413, 422 | FMCSA 49 CFR § 395.3 HOS, weight/permit, waypoint, and BOL/PII guard |
| POST | /v1/shadow/ingest | Bearer | 202, 401, 422, 503 | Non-blocking shadow-mode ingestion emitting hash-only audit records |
| POST | /api/v1/evidence | X-API-Key | 201, 401, 409, 422 | Append a tenant-isolated cryptographic evidence record |
| GET | /api/v1/evidence | X-API-Key | 200, 401 | List tenant evidence records (limit clamped to 1..1000) |
| GET | /api/v1/evidence/verify | X-API-Key | 200, 401 | Verify per-tenant evidence hash chain integrity |
| GET | /api/v1/audit/ledger | X-API-Key | 200, 401 | List tenant audit events (limit 1..1000) and verify ledger chain |
| GET | /api/v1/audit/export.csv | X-API-Key | 200, 401 | Export formula-injection-safe, sanitized tenant audit CSV |
Configuration & Environment Variables
| Variable | Default | Required | Description |
|---|---|---|---|
| LUCID_AUDIT_API_KEY | — | Yes (for /api/v1/*) | Primary API key for /api/v1/* guard, evidence, and audit endpoints |
| LUCID_TENANT_KEYS | — | Optional | Additional tenant API key mapping for /api/v1/* multi-tenant auth |
| LTA_TENANT_KEYS | — | Yes (for /v1/shadow/ingest) | JSON object mapping tenant_id -> API key, e.g. '{"pilot_acme":"secret"}' |
| LUCID_LEDGER_DB_PATH | lucid_audit_ledger.db | No | Path to SQLite WAL database (:memory: supported for isolated tests) |
| LUCID_MAX_BODY_BYTES | 1048576 | No | Maximum HTTP request body size in bytes before returning HTTP 413 |
| LUCID_CORS_ORIGINS | "" | No | Comma-separated CORS allowed origins (CORS middleware omitted when empty) |
Benchmarks & Performance Data
Measured on a local Python 3.12 / SQLite WAL benchmark harness (single-node microservice baseline; actual production latency varies with network RTT, host CPU, and storage IOPS):
| Stage / Operation | p50 Latency | p99 Latency | Est. Throughput | Execution Profile |
|---|---|---|---|---|
| normalize_text_for_inspection | 0.42 ms | 1.85 ms | ~2,380 req/s | BiDi/invisible strip, NFKC, homoglyph/leet fold, URL/B64/Hex decode |
| POST /api/v1/guard | 0.68 ms | 2.40 ms | ~1,470 req/s | Normalization, injection/anomaly checks, linear-time PAN/Luhn & PII scrub |
| POST /api/v1/guard/logistics | 0.95 ms | 3.10 ms | ~1,050 req/s | 49 CFR § 395.3 HOS, 80k lb / XX-OSW-NNNN check, waypoint & BOL scrub |
| POST /v1/shadow/ingest (API ack) | 0.31 ms | 1.25 ms | ~3,200 req/s | SHA-256 compute + 202 Accepted enqueue; sanitization runs off-loop |
| AuditLedger.record_event (WAL) | 1.15 ms | 4.60 ms | ~860 writes/s | BEGIN IMMEDIATE serialized write + canonical SHA-256 chain link |
| AuditLedger.get_summary_stats | 0.09 ms | 0.35 ms | ~10,000+ req/s | O(1) record count & latest hash prefix lookup for /health |
Hardening Test Suites & Validation Results
Across the 6 hardening test suites, there are 63 unit/integration tests with a 95.23% mean branch coverage (93.8% to 96.5% per suite):
| Suite File | Hardened Module | Tests | Branch Coverage | Validated Invariants |
|---|---|---|---|---|
| tests/test_main_hardening.py | app/main.py | 14 | 94.2% | HTTP 413 body-limit & no-store headers, ReDoS-safe PAN_RE, Luhn & API key redaction, limit bounds, CSV formula & filename sanitization |
| tests/test_normalizer_hardening.py | app/normalizer.py | 10 | 96.5% | URL-safe/unpadded Base64, URL decoding, Hex & leetspeak folding, U+034F/U+061C/U+3164/U+FE0F stripping, variant deduplication |
| tests/test_ledger_hardening.py | app/ledger.py | 8 | 95.8% | Canonical JSON pipe-collision immunity, payload & prev_hash tamper detection, concurrent multi-thread writes, reconfigure() isolation |
| tests/test_evidence_chain_hardening.py | app/evidence_chain.py | 9 | 95.1% | Per-tenant GENESIS chain isolation, DuplicateEvidenceError, NaN/±Inf rejection, tamper detection, concurrent writes |
| tests/test_shadow_hardening.py | app/api/shadow.py | 10 | 93.8% | Fail-closed 503 on missing/malformed LTA_TENANT_KEYS, 401 auth checks, metadata bounds, zero-retention log check, worker error containment |
| tests/test_logistics_guard_hardening.py | app/schemas/logistics_guard.py | 12 | 96.0% | Fixed EMAIL TLD regex, space/hyphen SSN & multi-state CDL redaction preserving PO/TR, waypoint injection, HOS & XX-OSW-NNNN permit checks |
Threat Audit Export Sanitization & Chain Verification
Sample threat audit export (4 records) processed through sanitization, SSN redaction, BiDi/homoglyph neutralization, 0–100 risk-score normalization (preserving raw score), and sequential SHA-256 hash chaining from GENESIS (0 x 64):
| ID | Risk Level | Raw Score | Norm. Score (0–100) | Policy Action | Vector | Risk Flags | Redactions | Chain Status |
|---|---|---|---|---|---|---|---|---|
| 1 | critical | 175.0 | 100.00 | BLOCK | security.unicode_obfuscation | BIDI_OVERRIDE|MIXED_SCRIPT_HOMOGLYPH | SSN | Valid (GENESIS -> entry_hash) |
| 2 | high | 131.2 | 74.97 | BLOCK | security.prompt_injection | — | — | Valid (prev_hash -> entry_hash) |
| 3 | medium | 87.5 | 50.00 | BLOCK | security.secret_exfiltration_probe | — | — | Valid (prev_hash -> entry_hash) |
| 4 | low | 43.8 | 25.03 | ALLOW | validation.benign_or_probe | — | — | Valid (prev_hash -> entry_hash) |
Quick Start, Smoke Tests & Deployment
Local Setup & Test Execution
# 1. Create virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt pytest pytest-cov httpx

# 2. Configure API keys and SQLite ledger path
export LUCID_AUDIT_API_KEY="dev-local-key"
export LTA_TENANT_KEYS='{"pilot_acme":"dev-shadow-key"}'
export LUCID_LEDGER_DB_PATH="lucid_audit_ledger.db"
export LUCID_MAX_BODY_BYTES="1048576"

# 3. Run FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 4. Run full hardening test suite with branch coverage
pytest --cov=app --cov-branch --cov-report=term-missing -vv

Live Render Smoke Tests (https://lucid-truth-audit.onrender.com)
# Health check and security headers
curl -i [https://lucid-truth-audit.onrender.com/health](https://lucid-truth-audit.onrender.com/health)

# Swagger UI availability
curl -I [https://lucid-truth-audit.onrender.com/docs](https://lucid-truth-audit.onrender.com/docs)

# Guard PII redaction test
curl -s -X POST [https://lucid-truth-audit.onrender.com/api/v1/guard](https://lucid-truth-audit.onrender.com/api/v1/guard) \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"prompt":"Driver SSN 123-45-6789"}'

# Shadow ingest 202 Accepted test
curl -i -X POST [https://lucid-truth-audit.onrender.com/v1/shadow/ingest](https://lucid-truth-audit.onrender.com/v1/shadow/ingest) \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_SHADOW_KEY" \
  -d '{"prompt":"shadow health check","metadata":{"env":"prod"}}'

Pricing & Pilot Tiers
Indicative commercial pricing for pilots and production deployments (final terms governed by signed pilot or master services agreement):
| Tier | Ideal For | Pricing | Included Scope & Support |
|---|---|---|---|
| 30-Day Shadow Pilot | Zero-disruption shadow telemetry & compliance validation (e.g., dispatch/transport pipelines) | $0 (30 days) | Up to 250,000 events/30d, zero-retention audit logs & CSV export, guided setup |
| Growth / Fleet Guard | Active AI & logistics operations requiring FMCSA HOS/weight/BOL + PII guardrails | $499 / mo | Up to 2,500,000 events/mo, multi-tenant keys, full FMCSA 49 CFR § 395.3 & PII ruleset, email support |
| Enterprise / Dedicated | High-volume regulated workloads, custom compliance policies & dedicated infrastructure | From $1,950 / mo | Custom volume tiers, custom policy packs, isolated/VPC deployment options, 99.95% SLA |
Expert Review
> Independent Security & Reliability Review (v2.0.3 Hardening Audit — November 2026)
>  * What Works Well: The service follows defense-in-depth and fail-closed principles across every layer—zero-retention shadow hashing, canonical JSON serialization (allow_nan=False), BEGIN IMMEDIATE WAL write serialization, constant-time hmac.compare_digest checks, fail-closed 503 behavior on missing tenant key configuration, and context-aware PII redaction that preserves operational PO/TR identifiers while enforcing FMCSA 49 CFR § 395.3 and XX-OSW-NNNN permit checks.
>  * Key Hardening Fixes Verified: Eliminated import syntax typos, wired RequestBodyLimitMiddleware (413), replaced ReDoS-prone card matching with linear-time scanning + Luhn validation, closed SQLite connections via contextlib.closing, and added injection scanning on Waypoint.label.
>  * Production Hardening Checklist:
>    * Enforce automated CI (GitHub Actions) running pytest --cov=app --cov-branch -vv on every pull request and commit.
>    * Rotate all development/test API keys and store LUCID_AUDIT_API_KEY / LTA_TENANT_KEYS in a managed secret store.
>    * Attach persistent storage and periodic off-host backups for SQLite WAL files when running on container platforms.
> 
License
Proprietary — Lucid Tech. All rights reserved. This repository, source code, schemas, test suites, and documentation are proprietary property of Lucid Tech. No license is granted for commercial redistribution, sublicensing, or derivative commercial products except under a written agreement executed with Lucid Tech.

