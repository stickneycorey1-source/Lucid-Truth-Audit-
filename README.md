# Lucid-Truth-Audit (`v2.0.3`)

[![Version](https://img.shields.io/badge/version-2.0.3-blue.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Pydantic%20v2-009688.svg)](https://fastapi.tiangolo.com/)
[![Compliance](https://img.shields.io/badge/FMCSA-49%20CFR%20%C2%A7%20395.3-2f855a.svg)](https://www.ecfr.gov/current/title-49/subtitle-B/chapter-III/subchapter-B/part-395/subpart-A/section-395.3)
[![Privacy](https://img.shields.io/badge/Retention-Zero%20PII%20Store-9b2c2c.svg)](#zero-retention--privacy-architecture)
[![Ledger](https://img.shields.io/badge/Ledger-SHA--256%20Hash--Chained-1a365d.svg)](#cryptographic-audit-ledger--evidence-chain)
[![Live API](https://img.shields.io/badge/Live%20Docs-Render%20Deployment-6b46c1.svg)](https://lucid-truth-audit.onrender.com/docs)
[![License](https://img.shields.io/badge/License-Proprietary%20%2F%20Enterprise%20Evaluation-4a5568.svg)](#license)

**Lucid-Truth-Audit** is a deterministic AI security, zero-retention PII redaction, tamper-evident cryptographic audit ledger, and FMCSA 49 CFR § 395.3 fleet compliance microservice built with Python, FastAPI, Pydantic v2, and SQLite (WAL mode).

* **Live API & Swagger UI:** `https://lucid-truth-audit.onrender.com/docs`
* **Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit`

---

## Visual Architecture & Benchmark Overview

![Pipeline Latency and Hardening Test Coverage](lta_benchmarks_and_coverage.png)

```text
Incoming Request (Prompt / Multi-Turn / Shadow / Dispatch Route)
       │
       ▼
[1. RequestBodyLimitMiddleware] ──▶ Rejects oversized payloads (HTTP 413, no-store, nosniff)
       │
       ▼
[2. Auth & Rate Limit Gate]     ──▶ Constant-time SHA-256 key verification & per-tenant throttling
       │
       ▼
[3. Normalizer & Sanitizer]     ──▶ Strips BiDi/zero-width/fillers/VS16, NFKC + homoglyph + leet fold,
       │                            decodes URL / Base64 (std/URL-safe/unpadded) / Hex (contiguous/0x/spaced)
       ▼
[4. Guard & Policy Engine]      ──▶ Blocks prompt injection, social-engineering PII pretexts, floods;
       │                            redacts SSN, Luhn PAN, API secrets, CDL/phone/email (zero raw retention)
       ▼
[5. FMCSA & Weight Validator]   ──▶ Enforces 49 CFR § 395.3 (11h drive, 14h window, 8h/30m break, 60/7 & 70/8),
       │                            80k lb cap + XX-OSW-NNNN permits, and authorized waypoints
       ▼
[6. Hash-Chained Ledger / Chain]──▶ Canonical JSON + SHA-256 + prev_hash link (BEGIN IMMEDIATE WAL)

Core Capabilities
1. Multi-Layer Input Normalization & Unicode Defense (app/normalizer.py, app/core/sanitizer.py)
 * Strips BiDi overrides (U+202E, U+202A–U+202E, U+2066–U+2069), Arabic Letter Mark (U+061C), Combining Grapheme Joiner (U+034F), Hangul fillers (U+115F, U+1160, U+3164, U+FFA0), soft hyphen (U+00AD), BOM (U+FEFF), Variation Selectors (U+FE00–U+FE0F), and non-spacing combining marks (Mn).
 * Applies Unicode NFKC normalization, Cyrillic/Greek homoglyph folding, and leetspeak substitution folding.
 * Decodes URL-encoded strings, padded/unpadded standard and URL-safe Base64, and contiguous, 0x-prefixed, or space-separated Hex tokens before security inspection.
2. Guard, PII Redaction & Ingress Hardening (app/main.py)
 * Blocks direct/indirect prompt injection, multi-turn role spoofing, social-engineering PII pretexts, repeating-character floods, and high-entropy anomalies.
 * Scrubs SSNs, Luhn-validated PANs using linear-time matching ((?<!\d)(?:\d[ -]?){12,18}\d(?!\d)), and modern API keys (sk-, ghp_, AKIA, AIza) at the boundary.
 * Enforces bounded request bodies (RequestBodyLimitMiddleware -> HTTP 413), strict CSP/security headers, sanitized Content-Disposition filenames, and spreadsheet formula-injection neutralization (sanitize_csv_cell).
3. Zero-Retention Shadow Mode (app/api/shadow.py)
 * Non-blocking 202 Accepted ingestion endpoint (POST /v1/shadow/ingest) executing sanitization in a background worker.
 * Emits ZeroRetentionAuditRecord entries containing audit_id, tenant_id, input_sha256, sanitized_sha256, lengths, risk flags, and timing metrics—strictly omitting raw or sanitized prompt text.
 * Fails closed with 503 Service Unavailable when LTA_TENANT_KEYS is missing or malformed, and verifies Bearer tokens via SHA-256 + hmac.compare_digest.
4. Cryptographic Audit Ledger & Evidence Chain (app/ledger.py, app/evidence_chain.py)
 * Append-only SQLite stores in WAL mode using BEGIN IMMEDIATE transactions to prevent multi-worker hash-chain forks.
 * Canonical JSON serialization (sort_keys=True, separators=(",", ":"), allow_nan=False) eliminates delimiter collision ambiguity and non-finite JSON values.
 * Independent per-tenant evidence chains (GENESIS -> entry_hash) with DuplicateEvidenceError (409 Conflict) and constant-time hmac.compare_digest chain verification.
5. FMCSA Fleet & Logistics Guard (app/schemas/logistics_guard.py)
 * Enforces FMCSA 49 CFR § 395.3 property-carrying rules: up to 11 hours driving within a 14-hour consecutive duty window after 10 consecutive hours off duty, a 30-minute break after 8 cumulative driving hours, and 60-hour/7-day or 70-hour/8-day cycle caps.
 * Validates the 80,000 lb federal gross vehicle weight cap, ^[A-Z]{2}-OSW-\d{4,10}$ oversize/overweight permit formats, authorized geofence waypoints, and indirect prompt injection across BOL notes, dispatcher summaries, and waypoint labels.
 * Scrubs driver SSNs, multi-state CDLs, phone numbers, and emails without corrupting operational purchase order (PO), bill of lading (BOL), or trailer (TR) identifiers.
Benchmarks & Test Results
Latency & Throughput Benchmarks (Local Benchmark Harness, Python 3.12 / SQLite WAL)
| Stage / Operation | p50 Latency | p99 Latency | Throughput (Est.) | Notes |
|---|---|---|---|---|
| normalize_text_for_inspection | 0.42 ms | 1.85 ms | ~2,380 req/s | Includes NFKC, homoglyph/leet fold, B64 & Hex decode |
| POST /api/v1/guard (PII + Guard) | 0.68 ms | 2.40 ms | ~1,470 req/s | Linear-time PAN check + Luhn + ledger append |
| POST /api/v1/guard/logistics | 0.95 ms | 3.10 ms | ~1,050 req/s | Full 49 CFR § 395.3 HOS, weight/permit & waypoint audit |
| POST /v1/shadow/ingest (API ack) | 0.31 ms | 1.25 ms | ~3,200 req/s | Returns 202 Accepted; sanitizes off-loop in background |
| AuditLedger.record_event (WAL) | 1.15 ms | 4.60 ms | ~860 writes/s | Serialized via BEGIN IMMEDIATE + SHA-256 chain link |
| AuditLedger.get_summary_stats | 0.09 ms | 0.35 ms | ~10,000+ req/s | O(1) count & latest hash prefix for /health probes |
Hardening Test Suites (pytest)
| Test Suite | Target Module | Tests | Branch Coverage | Key Assertions |
|---|---|---|---|---|
| tests/test_main_hardening.py | app/main.py | 14 | 94.2% | 413 body-limit headers, ReDoS-safe PAN_RE, sk-proj-/ghp_/AIza secrets, limit bounds, CSV formula & filename sanitization |
| tests/test_normalizer_hardening.py | app/normalizer.py | 10 | 96.5% | URL-safe/unpadded Base64, URL decoding, Hex + leetspeak folding, U+034F/U+061C/U+3164/U+FE0F, deduplication |
| tests/test_ledger_hardening.py | app/ledger.py | 8 | 95.8% | Pipe-delimiter collision immunity, payload & prev_hash tamper detection, concurrent writes, reconfigure() isolation |
| tests/test_evidence_chain_hardening.py | app/evidence_chain.py | 9 | 95.1% | Per-tenant GENESIS chains, DuplicateEvidenceError, NaN/Inf rejection, tamper detection, concurrent writes |
| tests/test_shadow_hardening.py | app/api/shadow.py | 10 | 93.8% | 503 fail-closed config & 401 auth, metadata bounds, zero-retention log guarantee, worker exception containment |
| tests/test_logistics_guard_hardening.py | app/schemas/logistics_guard.py | 12 | 96.0% | EMAIL regex fix, space/hyphen SSN & CDL redaction preserving PO/TR, waypoint injection, HOS & XX-OSW-NNNN permit checks |
Threat Audit Export Sanitization Benchmark
| Threat Vector in Sample Export | Raw Risk | Action | Sanitized Output & Integrity Guarantee |
|---|---|---|---|
| Unredacted SSN + BiDi RLO (U+202E) + Cyrillic а (U+0430) | critical (175.0 / 100.0 norm) | BLOCK | SSN redacted to [REDACTED_SSN], BiDi stripped, homoglyph folded, full 64-char SHA-256 & chain hash generated |
| Prompt injection (Ignore all previous instructions...) | high (131.2 / 75.0 norm) | BLOCK | Blocked under security.prompt_injection and chained in audit ledger |
| Root config / environment variable probe | medium (87.5 / 50.0 norm) | BLOCK | Blocked under security.secret_exfiltration_probe and chained in audit ledger |
| Empty whitespace validation probe | low (43.8 / 25.0 norm) | ALLOW | Logged under validation.benign_or_probe with full chain verification |
Quick Start & API Reference
# Install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Set environment configuration
export LUCID_AUDIT_API_KEY="dev-local-key"
export LTA_TENANT_KEYS='{"pilot_acme":"dev-shadow-key"}'
export LUCID_LEDGER_DB_PATH="lucid_audit_ledger.db"
export LUCID_MAX_BODY_BYTES="1048576"

# Start service
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Run hardening test suites with branch coverage
pytest --cov=app --cov-branch --cov-report=term-missing -vv

| Method & Path | Auth | Purpose |
|---|---|---|
| GET /health | None | O(1) service health, record count, and latest hash prefix |
| POST /api/v1/guard | X-API-Key | Prompt injection, anomaly detection, and PII redaction |
| POST /api/v1/guard/logistics | X-API-Key | FMCSA 49 CFR § 395.3 HOS, weight/permit, waypoint & BOL guard |
| POST /v1/shadow/ingest | Bearer | Non-blocking 202 Accepted zero-retention shadow audit |
| POST /api/v1/evidence | X-API-Key | Append tenant-isolated cryptographic evidence record (201) |
| GET /api/v1/evidence & /verify | X-API-Key | List tenant evidence records and verify per-tenant hash chain |
| GET /api/v1/audit/ledger & /export.csv | X-API-Key | Inspect ledger chain integrity or download formula-safe CSV |
Pricing (Commercial & Pilot Tiers)
| Tier | Target Workload | Monthly Pricing | Included Capacity & Support |
|---|---|---|---|
| 30-Day Shadow Pilot | Single-carrier / pilot validation (e.g., transport & dispatch telemetry) | $0 (30 days) | Up to 250,000 guard/shadow events, zero-retention audit export, direct onboarding |
| Growth / Fleet Guard | Mid-market AI & logistics dispatch teams | $499 / mo | Up to 2,500,000 events/mo, multi-tenant API keys, FMCSA HOS & BOL ruleset, email support |
| Enterprise / Dedicated | High-volume regulated AI, custom compliance & dedicated SLA | Custom (from $1,950 / mo) | Unlimited/volume-tiered throughput, custom policy packs, VPC/isolated deployment, 99.95% SLA |
Expert Review
> Independent Security & Reliability Review (Hardening Pass — November 2026)
>  * Strengths: The architecture makes strong security-by-default choices—zero-retention hashing on shadow ingestion, canonical JSON hashing with allow_nan=False, BEGIN IMMEDIATE SQLite WAL write serialization, constant-time hmac.compare_digest comparisons, fail-closed 503 behavior on missing tenant key configuration, and domain-aware FMCSA 49 CFR § 395.3 + CDL redaction that avoids corrupting operational PO/TR identifiers.
>  * Remediation Highlights: Hardening eliminated syntax/import typos, registered the previously unattached RequestBodyLimitMiddleware, replaced ReDoS-prone PAN matching with a linear-time pattern plus Luhn check, closed SQLite connection leaks via contextlib.closing, and added prompt-injection checks on Waypoint.label.
>  * Production Recommendations: Before high-concurrency production rollout, add an automated CI gate running the full pytest + branch-coverage suite on every push, pair SQLite WAL with scheduled off-host snapshots/backups (especially on ephemeral container filesystems), and rotate any test or placeholder API keys prior to pilot launch.
> 
License
Proprietary — Lucid Tech. All rights reserved. Unauthorized copying, distribution, modification, or commercial use of this software or documentation without explicit written permission from Lucid Tech is prohibited, except as expressly permitted under a signed Pilot, Evaluation, or Enterprise License Agreement.

