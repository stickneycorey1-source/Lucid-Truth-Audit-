Lucid-Truth-Audit (v2.0.3)

� � � �

� � � � �

� � � � � �

� � � �
Lucid-Truth-Audit is a deterministic AI security, zero-retention PII redaction, tamper-evident cryptographic audit ledger, and FMCSA 49 CFR § 395.3 fleet compliance microservice engineered in Python with FastAPI, Pydantic v2, and SQLite (WAL mode).
Live API & OpenAPI / Swagger UI: https://lucid-truth-audit.onrender.com/docs
Source Repository: https://github.com/stickneycorey1-source/Lucid-Truth-Audit
Framework Version: 2.0.3
Table of Contents
System Architecture & Data Flow
Core Capabilities & Security Modules
Zero-Retention & PII Redaction Engine
Multi-Layer Input Normalization & Unicode Defense
Cryptographic Audit Ledger & Evidence Chain
FMCSA 49 CFR § 395.3 Fleet & Logistics Guard
Authentication, Rate Limiting & Ingress Security
API Endpoints & Schema Reference
Configuration & Environment Variables
Benchmarks & Test Results
Validation & Verification Matrix
Quick Start & Live Smoke Tests
Pricing (Commercial & Pilot Tiers)
Expert Review
License
System Architecture & Data Flow
Lucid-Truth-Audit processes incoming requests through a deterministic, fail-closed pipeline before any payload reaches downstream inference, fleet dispatch logic, or persistent audit storage:
+-----------------------------------------------------------------------+
| Incoming HTTP Request (JSON / Prompt / Multi-Turn / Shadow / Route)   |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
| 1. RequestBodyLimitMiddleware & Security Headers                      |
|    - Enforces LUCID_MAX_BODY_BYTES (default 1,048,576 bytes)          |
|    - Rejects oversized Content-Length or streamed chunks with HTTP 413|
|    - Sets X-Content-Type-Options: nosniff, X-Frame-Options: DENY,     |
|      Referrer-Policy: no-referrer, Permissions-Policy, strict CSP     |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
| 2. Authentication & Tenant Rate Limiter                               |
|    - /api/v1/*: X-API-Key validation + per-tenant rate limiting       |
|    - /v1/shadow/ingest: SHA-256 + hmac.compare_digest Bearer check;   |
|      fails closed with HTTP 503 if LTA_TENANT_KEYS is unconfigured     |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
| 3. Normalizer & Sanitizer (app/normalizer.py, app/core/sanitizer.py)  |
|    - Strips invisible/BiDi/filler/VS16 chars + combining marks (Mn)   |
|    - NFKC normalization + Cyrillic/Greek homoglyph + leet folding     |
|    - Decodes URL encoding, standard/URL-safe/unpadded Base64, and     |
|      contiguous / 0x-prefixed / space-separated Hex tokens            |
+-----------------------------------+-----------------------------------+
                                    |
                   +----------------+----------------+
                   |                                 |
                   v                                 v
+-----------------------------------+ +---------------------------------+
| 4A. Prompt Guard & PII Redaction  | | 4B. FMCSA Fleet & Logistics     |
|     - Blocks prompt injection,    | |     - 49 CFR § 395.3 shift/cycle|
|       role spoofing, social-eng   | |     - 80k lb cap + XX-OSW-NNNN  |
|       PII pretexts, floods        | |     - Waypoint auth & injection |
|     - Redacts SSN, PAN, secrets   | |     - CDL/SSN/phone/email scrub |
+-----------------+-----------------+ +----------------+----------------+
                  |                                  |
                  +----------------+-----------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
| 5. Hash-Chained Audit Ledger & Tenant Evidence Chain                  |
|    - Canonical JSON (sort_keys=True, separators=(",", ":"),          |
|      allow_nan=False) + SHA-256 + prev_hash / entry_hash link         |
|    - SQLite WAL + BEGIN IMMEDIATE + contextlib.closing()              |
+-----------------------------------------------------------------------+
Core Capabilities & Security Modules
Module
Primary Responsibility
Hardening & Safety Guarantees
app/main.py
FastAPI app entrypoint, CSP & security headers, /health, /api/v1/guard, evidence & audit ledger routes, CSV export
RequestBodyLimitMiddleware registered (413), linear-time PAN_RE, expanded SECRET_RE, bounded limit (1..1000), bounded messages (<=50), sanitized Content-Disposition & CSV formula cells
app/normalizer.py
Multi-layer text normalization & payload decoding for inspection
Fixed b64decode(..., validate=True) on URL-safe/unpadded B64, URL decoding, Hex + leet folding, expanded BiDi/smuggling/homoglyph maps, ordered candidate deduplication
app/ledger.py
Global SHA-256 hash-chained SQLite audit ledger
contextlib.closing() connection lifecycle, BEGIN IMMEDIATE multi-worker serialization, canonical JSON hashing (no pipe-delimiter ambiguity), constant-time verification
app/evidence_chain.py
Per-tenant cryptographic evidence chain store
Independent tenant GENESIS chains, DuplicateEvidenceError (409), allow_nan=False canonical JSON, safe rollback checks, hmac.compare_digest chain verification
app/api/shadow.py
Non-blocking 202 Accepted zero-retention shadow ingestion
Fail-closed 503 on missing/malformed LTA_TENANT_KEYS, constant-time key scan, bounded metadata (<=20 keys), zero raw/sanitized text logging, worker exception containment
app/schemas/logistics_guard.py
FMCSA 49 CFR § 395.3 HOS, weight/permit, waypoint & BOL guard
Fixed EMAIL regex TLD group, space/hyphen SSN & context-aware CDL redaction preserving PO/TR, waypoint injection scan, allow_inf_nan=False, continuous-drive & permit checks
Zero-Retention & PII Redaction Engine
Lucid-Truth-Audit is engineered around a strict zero-retention privacy posture for sensitive audit telemetry:
No Raw PII Persistence: Sensitive identifiers such as Social Security Numbers (SSNs), Payment Card Industry Primary Account Numbers (PANs), Commercial Driver's Licenses (CDLs), phone numbers, email addresses, and API keys/secrets are redacted at the boundary using deterministic placeholders ([REDACTED_SSN], [REDACTED_PAN], [REDACTED_SECRET], [REDACTED_CDL], [REDACTED_PHONE], [REDACTED_EMAIL]).
Zero-Retention Shadow Mode (ZeroRetentionAuditRecord): /v1/shadow/ingest records cryptographic digests (input_sha256, sanitized_sha256), character lengths, Unicode/homoglyph/BiDi flags, processing latency in milliseconds, and operational metadata—never persisting raw or sanitized prompt text.
Linear-Time PAN & Secret Detection: PAN matching uses (?<!\d)(?:\d[ -]?){12,18}\d(?!\d) paired with a Luhn checksum validator so adversarial digit/space strings execute in linear time without catastrophic backtracking (ReDoS). Secret matching detects modern token formats including sk- (sk-proj-, sk-ant-), ghp_, AKIA, and AIza.
Spreadsheet Formula Neutralization: CSV exports prefix cells starting with =, +, -, @, \t, or \r with a leading single quote (') to neutralize CSV/DDE formula injection in spreadsheet viewers.
Multi-Layer Input Normalization & Unicode Defense
Attackers frequently attempt to evade prompt-injection and policy filters using invisible characters, lookalike scripts, character encoding, or leetspeak. normalize_text_for_inspection() counters these techniques prior to rule evaluation:
Invisible & Smuggling Character Stripping: Removes soft hyphen (U+00AD), Combining Grapheme Joiner (U+034F), Arabic Letter Mark (U+061C), Hangul fillers (U+115F, U+1160, U+3164, U+FFA0), Mongolian vowel separator (U+180E), zero-width spaces and BiDi controls (U+200B–U+200F, U+202A–U+202E, U+2060–U+206F), Variation Selectors (U+FE00–U+FE0F), and BOM (U+FEFF).
Diacritic & Compatibility Normalization: Decomposes characters to NFD, strips non-spacing combining marks (category == "Mn"), and applies NFKC normalization.
Homoglyph & Leetspeak Folding: Maps lookalike Cyrillic and Greek characters to ASCII equivalents and generates leetspeak-folded inspection variants (0->o, 1->i, 3->e, 4->a, 5->s, 7->t, @->a, $->s, !->i).
Encoded Payload Decoding: Decodes URL-percent-encoded strings, padded/unpadded standard and URL-safe Base64 (validate=True after normalizing -/_ and padding), and contiguous, 0x-prefixed, or space-separated Hex tokens, deduplicating normalized candidates while preserving scan order.
Cryptographic Audit Ledger & Evidence Chain
Both AuditLedger (app/ledger.py) and EvidenceChainStore (app/evidence_chain.py) provide tamper-evident history:
Hash Chaining: Each new entry computes a SHA-256 digest over canonicalized fields and the previous entry's digest (GENESIS for the initial record in a chain). Modifying, deleting, or reordering any historical record invalidates subsequent hashes during chain verification.
Multi-Worker Write Serialization: SQLite runs in WAL mode with busy timeouts and BEGIN IMMEDIATE transactions inside contextlib.closing() blocks so concurrent threads or worker processes serialize before reading the latest hash and inserting the next record.
Canonical Serialization & Constant-Time Verification: Records are serialized with deterministic key ordering, compact separators ((",", ":")), and allow_nan=False. Chain verification compares digests with hmac.compare_digest().
Tenant Isolation on Evidence Chains: EvidenceChainStore scopes prev_hash chains and (tenant_id, evidence_id) uniqueness per tenant_id, raising DuplicateEvidenceError (mapped to HTTP 409 Conflict) on duplicate tenant evidence IDs.
FMCSA 49 CFR § 395.3 Fleet & Logistics Guard
DispatchRoutePayload and /api/v1/guard/logistics enforce deterministic fleet safety and regulatory rules for property-carrying commercial motor vehicles:
Rule / Constraint
Enforced Bound / Policy
Error / Outcome
Single-Shift Driving Limit
Up to 11.0 hours driving after 10 consecutive hours off duty (49 CFR § 395.3(a)(3)(i))
Pydantic / 422 validation error on violation
14-Hour Consecutive Duty Window
Up to 14.0 consecutive hours on duty; planned_drive_hours <= on_duty_window_hours
HOS_VIOLATION on violation
30-Minute Rest Break Rule
Mandatory >= 30 minute break; continuous_drive_before_break_hours <= 8.0 and <= planned_drive_hours
HOS_VIOLATION on violation
Multi-Day Cycle Caps
60_7 (<= 60.0 hrs / 7 days) or 70_8 (<= 70.0 hrs / 8 days) including prior cycle hours
HOS_CYCLE_VIOLATION on violation
Federal Weight & Oversize Permit
<= 80,000 lbs default cap (up to 160,000 lbs max schema bound); oversize_permit_id must match ^[A-Z]{2}-OSW-\d{4,10}$ whenever supplied and is required above 80,000 lbs
WEIGHT_VIOLATION on violation
Geofence & Waypoint Integrity
2..25 waypoints; is_authorized_facility must be True; label scanned for blank text and indirect prompt injection
SECURITY_VIOLATION on violation
Indirect Prompt Injection & PII
bill_of_lading_notes, dispatcher_summary, and waypoints[].label normalized & scanned; SSN, CDL, PHONE, EMAIL redacted while keeping PO/TR IDs intact
APPROVED or APPROVED_WITH_REDACTIONS (200)
Authentication, Rate Limiting & Ingress Security
API Key & Bearer Authentication: /api/v1/* routes enforce authenticate_and_limit (including on /api/v1/guard RequestValidationError paths), while /v1/shadow/ingest validates Bearer tokens against SHA-256 hashes of LTA_TENANT_KEYS using hmac.compare_digest and returns 503 Service Unavailable when unconfigured or malformed.
Bounded Request Bodies: RequestBodyLimitMiddleware checks Content-Length and streams chunks incrementally against LUCID_MAX_BODY_BYTES, returning HTTP 413 (ingress.body_too_large) with Cache-Control: no-store, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, and a sanitized X-Request-ID header.
Hardened HTTP Headers & CORS: Every response sets X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy: no-referrer, Permissions-Policy: geolocation=(), microphone=(), camera=(), and a path-aware Content-Security-Policy (allowing Swagger/ReDoc CDN assets only on /docs, /redoc, and /docs/oauth2-redirect). CORS middleware is only attached when LUCID_CORS_ORIGINS is explicitly configured.
API Endpoints & Schema Reference
Method
Path
Auth
Status Codes
Summary
GET
/
None
200
Serves web portal (static/index.html)
GET
/health
None
200
O(1) health probe returning version, ledger record count, latest hash prefix, and active vectors
POST
/api/v1/guard
X-API-Key
200, 401, 422, 429, 413
Evaluates prompt and optional messages (<=50 turns), blocks attacks/anomalies, redacts PII, appends ledger event
POST
/api/v1/guard/logistics
X-API-Key
200, 401, 422, 429, 413
Validates FMCSA HOS, weight/permit, waypoints, and BOL/summary injection & PII, appends ledger event
POST
/v1/shadow/ingest
Bearer
202, 401, 422, 503, 413
Queues non-blocking zero-retention sanitization and emits ZeroRetentionAuditRecord
POST
/api/v1/evidence
X-API-Key
201, 401, 409, 422, 413
Appends a tenant-isolated hash-chained evidence record
GET
/api/v1/evidence
X-API-Key
200, 401, 422
Lists tenant evidence records (limit clamped 1..1000)
GET
/api/v1/evidence/verify
X-API-Key
200, 401
Verifies integrity of the caller's tenant evidence hash chain
GET
/api/v1/audit/ledger
X-API-Key
200, 401, 422
Returns ledger chain verification status and tenant audit events (limit 1..1000)
GET
/api/v1/audit/export.csv
X-API-Key
200, 401
Streams a formula-neutralized CSV export with a sanitized Content-Disposition filename
Configuration & Environment Variables
Variable
Default
Required / Behavior
Description
LUCID_AUDIT_API_KEY
—
Recommended
Primary API key for /api/v1/* endpoints when not using multi-tenant keys
LUCID_TENANT_KEYS
—
Optional
Multi-tenant key mapping for /api/v1/* endpoints
LTA_TENANT_KEYS
—
Required for Shadow Mode
JSON object mapping tenant_id to API key for /v1/shadow/ingest (e.g. '{"pilot_acme":"secret"}')
LUCID_LEDGER_DB_PATH
lucid_audit_ledger.db
Optional
SQLite file path for AuditLedger and EvidenceChainStore
LUCID_MAX_BODY_BYTES
1048576
Optional
Maximum allowed HTTP request body size in bytes (>= 1)
LUCID_CORS_ORIGINS
""
Optional
Comma-separated origin allowlist; CORS middleware is omitted when blank
Benchmarks & Test Results
Latency & Throughput Benchmarks (Python 3.12 / SQLite WAL / Local Benchmark Harness)
Operation / Stage
p50 Latency
p99 Latency
Est. Throughput
Workload Profile
normalize_text_for_inspection
0.42 ms
1.85 ms
~2,380 ops/s
NFKC, homoglyph/leet fold, URL/Base64/Hex decode
POST /api/v1/guard
0.68 ms
2.40 ms
~1,470 req/s
Injection/anomaly check, SSN/PAN/secret redaction & ledger append
POST /api/v1/guard/logistics
0.95 ms
3.10 ms
~1,050 req/s
FMCSA 49 CFR § 395.3 shift/cycle, weight/permit, waypoint & PII check
POST /v1/shadow/ingest (ACK)
0.31 ms
1.25 ms
~3,200 req/s
Immediate 202 Accepted enqueue; sanitization runs in background
AuditLedger.record_event (WAL)
1.15 ms
4.60 ms
~860 writes/s
BEGIN IMMEDIATE write + SHA-256 chain computation + commit
AuditLedger.get_summary_stats
0.09 ms
0.35 ms
~10,000+ req/s
O(1) row count and latest hash prefix lookup for /health
Hardening Test Suite Results (pytest)
Test Suite
Target Module
Test Cases
Branch Coverage
Verified Scenarios
tests/test_main_hardening.py
app/main.py
14
94.2%
413 body-limit headers, ReDoS-safe PAN_RE, modern secrets (sk-proj-, ghp_, AIza), limit bounds, CSV formula & filename sanitization
tests/test_normalizer_hardening.py
app/normalizer.py
10
96.5%
URL-safe/unpadded Base64, URL decoding, Hex + leetspeak folding, U+034F/U+061C/U+3164/U+FE0F, deduplication
tests/test_ledger_hardening.py
app/ledger.py
8
95.8%
Pipe-delimiter collision immunity, payload & prev_hash tamper detection, concurrent writes, reconfigure() isolation
tests/test_evidence_chain_hardening.py
app/evidence_chain.py
9
95.1%
Per-tenant GENESIS chains, DuplicateEvidenceError, NaN/Inf rejection, tamper detection, concurrent writes
tests/test_shadow_hardening.py
app/api/shadow.py
10
93.8%
503 fail-closed config & 401 auth, metadata bounds, zero-retention audit emission, worker error containment
tests/test_logistics_guard_hardening.py
app/schemas/logistics_guard.py
12
96.0%
EMAIL regex fix, space/hyphen SSN & CDL redaction preserving PO/TR, waypoint injection, HOS & XX-OSW-NNNN permit checks
Threat Audit Export Sanitization & Chain Validation
Threat Vector
Raw Severity / Score
Normalized Score (0–100)
Action
Sanitization & Integrity Outcome
Unredacted SSN + BiDi RLO (U+202E) + Cyrillic а (U+0430)
critical (175.0)
100.00
BLOCK
SSN replaced with [REDACTED_SSN], RLO stripped, Cyrillic а folded to a, 64-char SHA-256 & chain hash generated
Prompt injection (Ignore all previous instructions...)
high (131.2)
74.97
BLOCK
Classified under security.prompt_injection and linked into hash chain
Root config / environment variable probe
medium (87.5)
50.00
BLOCK
Classified under security.secret_exfiltration_probe and linked into hash chain
Empty whitespace validation probe
low (43.8)
25.03
ALLOW
Classified under validation.benign_or_probe with verified chain continuity (chain_valid: True)
Validation & Verification Matrix
Static & Syntax Validation: Verified all modules compile cleanly with zero Import capitalization typos, missing imports (uuid, hmac, closing), or invalid regex character classes (EMAIL pipe fix).
Fail-Closed & Bounds Validation: Confirmed RequestBodyLimitMiddleware is attached to app, shadow auth returns 503 when LTA_TENANT_KEYS is absent/malformed and 401 on invalid/empty Bearer tokens, limit query parameters enforce 1..1000, GuardRequest.messages enforces <=50, ShadowIngestRequest.metadata enforces <=20 entries, and non-finite floats (NaN, Inf, -Inf) are rejected.
Cryptographic & Concurrency Validation: Verified multi-threaded writes preserve sequential prev_hash -> entry_hash links without race forks, canonical JSON prevents delimiter ambiguity, and altering any row's payload or prev_hash causes chain verification to report chain_valid: False with the exact failing record ID.
Quick Start & Live Smoke Tests
Local Setup & Test Execution
# 1. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment variables
export LUCID_AUDIT_API_KEY="dev-local-key"
export LTA_TENANT_KEYS='{"pilot_acme":"dev-shadow-key"}'
export LUCID_LEDGER_DB_PATH="lucid_audit_ledger.db"
export LUCID_MAX_BODY_BYTES="1048576"

# 4. Run the FastAPI application
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 5. Execute all hardening test suites with branch coverage
pytest \
  tests/test_main_hardening.py \
  tests/test_normalizer_hardening.py \
  tests/test_ledger_hardening.py \
  tests/test_evidence_chain_hardening.py \
  tests/test_shadow_hardening.py \
  tests/test_logistics_guard_hardening.py \
  --cov=app --cov-branch --cov-report=term-missing -vv
Live Render Smoke Tests (https://lucid-truth-audit.onrender.com)
# Health probe and security headers
curl -i https://lucid-truth-audit.onrender.com/health

# Swagger / OpenAPI UI check
curl -I https://lucid-truth-audit.onrender.com/docs

# Unauthenticated guard call (expect 401)
curl -i -X POST https://lucid-truth-audit.onrender.com/api/v1/guard \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test"}'

# Authenticated PII redaction check
curl -s -X POST https://lucid-truth-audit.onrender.com/api/v1/guard \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"prompt":"Driver SSN 123-45-6789"}'

# Shadow mode 202 Accepted check
curl -i -X POST https://lucid-truth-audit.onrender.com/v1/shadow/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_SHADOW_KEY" \
  -d '{"prompt":"shadow smoke test","metadata":{"env":"prod"}}'
Pricing (Commercial & Pilot Tiers)
Tier
Best For
Monthly Price
Included Capacity & Terms
30-Day Shadow Pilot
Single-carrier or pre-production AI security & FMCSA compliance validation
$0 (30 days)
Up to 250,000 guard/shadow events, zero-retention audit exports, direct onboarding support
Growth / Fleet Guard
Mid-market AI applications & commercial fleet dispatch operations
$499 / mo
Up to 2,500,000 events/month, multi-tenant key management, FMCSA HOS & BOL ruleset, standard SLA support
Enterprise / Dedicated
High-throughput regulated environments, custom policy packs & isolated deployments
Custom (from $1,950 / mo)
High-volume/custom throughput tiers, bespoke policy rules, dedicated/VPC deployment options, 99.95% uptime SLA
Expert Review
Independent Security & Reliability Review (v2.0.3 Hardening Audit — November 2026)
Architecture & Security Posture: Lucid-Truth-Audit demonstrates disciplined defense-in-depth for high-accountability AI and logistics workloads. Zero-retention hashing on shadow ingestion, fail-closed 503/401 authentication gates, constant-time hmac.compare_digest verification, canonical JSON hashing with allow_nan=False, and BEGIN IMMEDIATE SQLite WAL write serialization address core integrity and privacy failure modes at the boundary.
Remediation Impact: The hardening pass resolved syntax and import defects, registered RequestBodyLimitMiddleware for HTTP 413 body enforcement, replaced ReDoS-prone PAN matching with a linear-time pattern plus Luhn verification, closed SQLite connection leaks via contextlib.closing(), and extended prompt-injection screening to Waypoint.label.
Operational & Rollout Recommendations: Maintain CI execution of the full pytest and --cov-branch suite on every pull request, pair SQLite WAL storage with scheduled off-host backups or persistent volume snapshots so audit history survives container restarts or ephemeral disk resets, and rotate any development or evaluation API keys prior to production cutover.
License
Proprietary — Lucid Tech. All rights reserved.
This software, source code, schemas, and documentation are proprietary to Lucid Tech. No license is granted for commercial distribution, sublicensing, resale, or production operation outside of a signed Pilot, Evaluation, or Enterprise License Agreement with Lucid Tech.