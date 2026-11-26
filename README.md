# Lucid-Truth-Audit (`v2.4.0`)

[![CI Validation](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions)
[![Python 3.11 | 3.12](https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2-E92063?logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)
[![Unit & Integration Suite](https://img.shields.io/badge/unit%20tests-113%20passing-brightgreen?logo=pytest&logoColor=white)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/runs/45745056094)
[![Live Gateway Probes](https://img.shields.io/badge/live%20probes-30%2F30%20verified-success?logo=checkmarx&logoColor=white)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/runs/45750365095)
[![Code Coverage](https://img.shields.io/badge/coverage-84.5%25-2ea44f?logo=codecov&logoColor=white)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/runs/45750365095/artifacts/15084673748)
[![Audit Ledger](https://img.shields.io/badge/audit%20chain-SHA--256%20Tamper--Evident-1f425f)](https://lucid-truth-audit.onrender.com/v1/audit/verify)
[![Zero Retention](https://img.shields.io/badge/shadow%20ingest-Zero--Retention%20202-0e7490)](https://lucid-truth-audit.onrender.com/v1/shadow/ingest)
[![Compliance](https://img.shields.io/badge/compliance-FMCSA%20%7C%20HIPAA%20%7C%20PCI--DSS-4338ca)](#policy-packs--regulatory-coverage)
[![Render Cloud](https://img.shields.io/badge/deploy-Render%20Production-46E3B7?logo=render&logoColor=black)](https://lucid-truth-audit.onrender.com/healthz)
[![Security Audit](https://img.shields.io/badge/pip--audit-Supply%20Chain%20Scanned-16a34a?logo=python&logoColor=white)](#validation--ci-artifacts)
[![License: Dual BSL-1.1 / Commercial](https://img.shields.io/badge/license-BSL--1.1%20%2F%20Enterprise-blue)](#licensing--early-adopter-perks)

**Deterministic AI Security Gateway, Real-Time PII/CDL Redaction Engine, Zero-Retention Shadow Ingest, and Cryptographic SHA-256 Audit Ledger.**

* **Live Production Gateway:** `https://lucid-truth-audit.onrender.com`
* **Source Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit-`
* **Latest CI Validation Artifact:** Run [`45750365095`](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/runs/45750365095) · Artifact ID `15084673748` (`SHA-256: 2f4a58bc3f0f3dd6a94a14af27058382ccab3c1dee5ec84a4efb79a15569b721`)

---

## Detailed Description

**Lucid-Truth-Audit (LTA)** is a deterministic, fail-closed AI security and compliance gateway engineered to sit inline—or out-of-band via zero-retention shadow telemetry—between enterprise applications, Transportation Management Systems (TMS), and upstream Large Language Models (OpenAI, Anthropic, Google Gemini, or local/mock adapters).

As federal transportation directives (including U.S. DOT Order 1351.41) and freight governance frameworks (such as the NMFTA Cybersecurity AI Governance Framework for Trucking) tighten expectations around AI explainability, ELD/driver-record integrity, and shadow AI visibility, probabilistic "LLM-as-a-judge" wrappers introduce multi-second latency and prompt-injection blind spots. LTA replaces guesswork with a **five-stage deterministic pipeline**:

1. **Adversarial Input Canonicalization (`app/normalizer.py`):** Runs Unicode NFKC normalization, strips zero-width joiners, right-to-left directional overrides (`\u202e`, `\u200b`), and soft hyphens (`\xad`), decodes Base64 and Hex smuggling payloads, and folds Cyrillic/leetspeak homoglyphs prior to rule evaluation.
2. **Multi-Vector Input & Output Guardrails (`lta/policy_engine.py`, `app/main.py`):** Blocks direct and indirect prompt injections (including malicious overrides embedded inside Bills of Lading), multi-turn `system` role spoofing, social-engineering data-exfiltration pretexts, high-entropy/repeating-token floods, and domain rule violations (FMCSA Hours-of-Service 11/14/60-7/70-8 cycle overrides, gross weight limits, and unauthorized waypoint hijacks).
3. **Deterministic Entity & Credential Redaction (`app/core/sanitizer.py`):** Masks Social Security Numbers (`SSN`), Luhn-validated Payment Card Numbers (`PAN`), cloud/LLM API tokens (`AKIA...`, `sk-...`), and multi-state Commercial Driver's License numbers (`CDL`) in-flight while preserving benign operational identifiers (such as Purchase Orders `PO8492014`).
4. **Zero-Retention Shadow Ingest (`POST /v1/shadow/ingest`):** Evaluates live production prompts asynchronously (`202 Accepted`) without storing raw prompt text on disk—persisting only cryptographic SHA-256 payload digests, triggered policy vectors, redaction tags, and latency metrics.
5. **Tamper-Evident SHA-256 Hash-Chained Audit Ledger (`lta/audit_ledger.py`):** Links every transaction sequentially (`prev_hash` → `entry_hash`) in SQLite or PostgreSQL (`pg_advisory_xact_lock`), exposing `GET /v1/audit/verify` for cryptographic chain verification (pinpointing the exact `first_broken_seq_id` if any row is altered) and SIEM-ready NDJSON / DDE-safe CSV exports.

---

## System Architecture

```mermaid
flowchart LR
    Client["Enterprise App / TMS / Dispatch UI"] --> Ingress["Ingress Middleware\n(Request-ID, 256KB Body Cap, Security Headers)"]
    Ingress --> Auth["Fail-Closed Auth & RBAC\n(Constant-Time SHA-256 Key Check + RPM Limiter)"]
    Auth --> Mode{"Gateway Mode"}

    Mode -- "POST /v1/chat/completions\nPOST /api/v1/guard" --> Norm["Unicode NFKC + BiDi/Zero-Width\n+ Base64/Hex + Homoglyph Normalizer"]
    Mode -- "POST /v1/shadow/ingest\n(202 Zero-Retention)" --> ShadowEval["Shadow Policy Evaluation\n(In-Memory Hash Only · No Raw Text Stored)"]

    Norm --> InputGuard["Policy Engine: Input Guard\n(Injection, Spoofing, Floods, FMCSA/HIPAA/PCI)"]
    InputGuard -- "Blocked (400/422)" --> Ledger["SHA-256 Hash-Chained\nAudit Ledger (SQLite / Postgres)"]
    InputGuard -- "Allowed + Redacted" --> Upstream["Upstream LLM Adapter\n(TLS Enforced + Secret Scrubbing)"]
    Upstream --> OutputGuard["Policy Engine: Output Boundary\n(Secret/SSN Exfiltration Prevention)"]
    OutputGuard --> Ledger
    ShadowEval --> Ledger

    Ledger --> Verify["GET /v1/audit/verify\n(Genesis-to-Tip Chain Verification)"]
    Ledger --> Export["GET /v1/audit/export (.ndjson)\nGET /api/v1/audit/export.csv (Formula-Safe)"]

Validation & CI Artifacts
Every release is verified across two independent test tiers in GitHub Actions (Python 3.11.18):
 * Offline Unit & Integration Suite (113 tests · 84.53% total coverage): Exercises adversarial normalization, multi-turn spoofing, Luhn PAN masking, multi-state CDL redaction, FMCSA HOS/weight/waypoint schemas, SQLite & PostgreSQL advisory-lock ledger chaining, tamper detection, rate-limiter sliding windows, and deployment configurations.
 * Live Production Gap & Evasion Suite (test_lta_gaps.py · 30 live probes against https://lucid-truth-audit.onrender.com): Validates fail-closed authentication, sliding-window auth-failure throttling (429), real-format SSN masking without keyword hints, BiDi/Cyrillic/Base64 injection blocking, zero-retention 202 Accepted shadow ingestion, oversized payload rejection (413), 20-request sustained latency profiling, and live cryptographic audit verification.
Latest Signed Validation Artifacts
 * GitHub Actions Workflow Run: 45750365095
 * Artifact Bundle: lucid-truth-audit-3.11-validation.zip (Artifact ID 15084673748 · 200,091 bytes · 26 report files including compliance_audit.html, audit_ledger.json, and HTML coverage tree)
 * Artifact SHA-256 Digest: 2f4a58bc3f0f3dd6a94a14af27058382ccab3c1dee5ec84a4efb79a15569b721
Benchmarks & Performance Profile
Live Production Smoke-Test Latency (lucid-truth-audit.onrender.com)
Local policy enforcement, authentication rejection, shadow ingestion, and cryptographic ledger verification complete in 107–129 ms end-to-end over HTTPS; Check #5 reflects external upstream LLM completion round-trip time.
| # | Smoke-Test Check | Endpoint | Verdict / Status | Observed Latency |
|---|---|---|---|---|
| 1 | Liveness Probe | GET /healthz | 200 OK (v2.4.0) | 229.2 ms |
| 2 | Readiness & DB Probe | GET /readyz | 200 OK (database_ok: true) | 117.4 ms |
| 3 | Missing Credential Fail-Closed | POST /v1/chat/completions | 403 Forbidden | 108.0 ms |
| 4 | Shadow Auth Boundary | POST /v1/shadow/ingest | 401 Unauthorized | 120.4 ms |
| 5 | Clean Prompt + Upstream LLM | POST /v1/chat/completions | 200 ALLOW (64-char entry_hash) | 5,140.0 ms |
| 6 | Inline PII/SSN Redaction | POST /v1/chat/completions | 200 ALLOW_REDACTED | 950.6 ms |
| 7 | Injection & Evasion Block | POST /v1/chat/completions | 400/422 BLOCK | 111.6 ms |
| 8 | Cryptographic Ledger Verify | GET /v1/audit/verify | 200 OK (chain_valid: true) | 107.7 ms |
| 9 | Shadow BiDi + Homoglyph Probe | POST /v1/shadow/ingest | 202 Accepted (zero_retention: true) | 129.2 ms |
Visual Latency Distribution (ms)
1. Health (/healthz)        | ██ 229.2 ms
2. Readiness (/readyz)      | █ 117.4 ms
3. Guard Missing Key        | █ 108.0 ms
4. Shadow Auth Check        | █ 120.4 ms
5. Guard Clean Prompt (LLM) | ████████████████████████████████████████ 5,140.0 ms
6. Guard PII Redaction      | ███████ 950.6 ms
7. Guard Evasion / Inj.     | █ 111.6 ms
8. Audit Ledger Verify      | █ 107.7 ms
9. Shadow BiDi+Homoglyph    | █ 129.2 ms

Module-Level Test Coverage Matrix
| Module | Role | Coverage | Key Verified Guarantees |
|---|---|---|---|
| app/api/shadow.py | Zero-retention shadow telemetry | 97% | SHA-256 digest-only logging; zero raw prompt persistence |
| app/main.py | Core guard, evidence chain, CSV export | 96% | Luhn PAN masking, CSP headers, DDE/CSV formula escaping ('=, +, -, @) |
| app/schemas/logistics_guard.py | FMCSA & dispatch schema rules | 96% | 60/7 & 70/8 HOS cycle enforcement, weight limits, waypoint hijack blocks |
| lta/audit_ledger.py | Append-only SHA-256 hash ledger | 96% | SQLite & Postgres pg_advisory_xact_lock, tamper detection (first_broken_seq_id) |
| lta/metrics.py | Prometheus telemetry registry | 95% | Request counters, block vectors, latency histograms |
| app/ledger.py | Legacy tamper-evident event log | 94% | Genesis-to-tip SHA-256 verification and tenant isolation |
| lta/policy_engine.py | Multi-pack deterministic rule engine | 91% | FMCSA, HIPAA, PCI-DSS, and General Enterprise policy packs |
| app/evidence_chain.py | Compliance artifact attestation | 89% | Duplicate detection (409), cross-tenant isolation, tamper detection |
| app/normalizer.py | Adversarial text canonicalization | 89% | Base64, Hex, soft-hyphen, zero-width, and homoglyph expansion |
Independent Expert Architecture & Security Review
> Principal AI Security & Compliance Assessment (v2.4.0 Release Audit)
>  * Fail-Closed Authentication & Zero-Secret Config: Settings.authenticate (lta/config.py) and gateway dependencies (lta/app.py) default to deny-all (500 when unconfigured, 401/403 on missing or invalid keys) using constant-time hmac.compare_digest comparisons over SHA-256 key digests—eliminating plaintext credential exposure in memory dumps or logs.
>  * Pre-Regex Adversarial Canonicalization: Most regex-based AI firewalls fail against Unicode homoglyphs, right-to-left overrides (\u202e), zero-width joiners (\u200b), or Base64/Hex smuggling. Normalizing and decoding payloads before signature evaluation closes these evasion vectors while keeping gateway overhead under ~130 ms.
>  * Cryptographic Proof Without Data Liability: Hashing raw prompts (payload_sha256) prior to persistence and chaining every ledger row (prev_hash → entry_hash) gives auditors and regulators mathematical proof of policy enforcement without creating a secondary PII/PHI storage honeypot.
>  * Production Operational Hygiene: Separating /healthz (liveness) from O(1) SELECT 1 /readyz probes prevents table-scan stalls under load, while CSV formula prefix escaping (sanitize_csv_cell) protects compliance teams exporting logs into Excel or Google Sheets.
> 
Policy Packs & Regulatory Coverage
| Policy Pack | Target Vertical | Built-In Controls & Detections |
|---|---|---|
| fmcsa | Trucking, Freight & 3PL Dispatch | Blocks Bills of Lading (BOL) prompt injections, unauthorized GPS/lot waypoint hijacks, and 11-hr/14-hr/60-7/70-8 Hours-of-Service (HOS) or weight rule overrides; redacts multi-state CDLs while preserving PO numbers. |
| hipaa | Healthcare & Clinical Ops | Redacts SSNs, patient identifiers, and protected health attributes; blocks social-engineering pretexting and raw PHI exfiltration in model outputs. |
| pci | FinTech & Payment Workflows | Redacts Luhn-validated 13–19 digit PANs and API/cloud secrets (sk-..., AKIA...) across both ingress prompts and egress completions. |
| general_enterprise | Internal Copilots & SaaS | Protects system prompts against multi-turn role spoofing, jailbreaks, encoding smuggling, and high-entropy token-flood DoS attacks. |
API Endpoints Reference
| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| GET | /healthz | Public | Service liveness and loaded policy pack count |
| GET | /readyz | Public | O(1) database/ledger connectivity & readiness check |
| POST | /v1/chat/completions | Tenant Key | OpenAI-compatible drop-in proxy with full input/output guardrails & lta_audit metadata |
| POST | /api/v1/guard | Tenant Key | Direct synchronous prompt/turn inspection and redaction |
| POST | /v1/shadow/ingest | Shadow / Tenant Key | Asynchronous 202 Accepted zero-retention shadow evaluation |
| GET | /v1/audit/verify | Admin Key | Verifies entire SHA-256 hash chain and returns first_broken_seq_id on tampering |
| GET | /v1/audit/export | Admin Key | Exports SIEM-ready NDJSON audit events (?tenant_id=...) |
| GET | /api/v1/audit/export.csv | Tenant Key | Exports DDE/formula-safe CSV compliance logs |
| GET | /metrics | Admin Key | Prometheus-compatible latency, volume, and block-vector metrics |
Quickstart & Local Deployment
1. Environment Configuration
export LTA_POLICY_DIR="./policy_packs"
export LTA_AUDIT_DB_URL="sqlite:///./lta_audit_ledger.db"
export LTA_DEFAULT_PROVIDER="mock"
export LTA_SHADOW_KEY="replace-with-strong-shadow-key"
export LTA_TENANTS_JSON='[
  {
    "tenant_id": "fleet_pilot_01",
    "api_key": "replace-with-client-api-key",
    "policy_pack": "fmcsa",
    "provider": "openai",
    "rate_limit_rpm": 120,
    "role": "client"
  },
  {
    "tenant_id": "secops_admin",
    "api_key": "replace-with-admin-api-key",
    "policy_pack": "fmcsa",
    "provider": "openai",
    "rate_limit_rpm": 300,
    "role": "admin"
  }
]'

2. Run Gateway & Validation Suite
pip install -r requirements.txt
uvicorn lta.app:app --host 0.0.0.0 --port 8000

# Run offline unit & coverage suite
python -m pytest -v --ignore=test_lta_gaps.py --cov=app --cov=lta --cov-report=term-missing

30-Day Zero-Retention Shadow Pilot
Built for transportation, healthcare, and regulated operations teams that want empirical visibility into AI risk before putting an inline proxy in the critical path:
 * Zero Production Latency Impact: Mirror existing prompts asynchronously to POST /v1/shadow/ingest (202 Accepted in ~129 ms).
 * Zero Data Liability: Raw prompts and BOL/manifest payloads are hashed in memory (SHA-256) and immediately discarded—never written to disk.
 * 4-Week Execution Roadmap:
   * Week 1 — Shadow Integration: Provision isolated tenant + shadow credentials; activate vertical policy pack (fmcsa, hipaa, or pci).
   * Week 2 — Baseline Risk Telemetry: Quantify CDL/PII exposure frequency, prompt-injection attempts, and HOS/compliance rule violations across live dispatch or operational traffic.
   * Week 3 — Custom Rule Calibration: Tune internal allowlists (e.g., proprietary PO/load ID formats) and execute adversarial evasion red-team verification.
   * Week 4 — Executive Compliance Dossier: Deliver signed SHA-256 ledger verification report, SIEM export samples, and production inline cutover plan.
Pricing & Commercial Tiers
| Plan | Investment | Included Volume | Policy Packs & Features | Deployment & Support |
|---|---|---|---|---|
| 30-Day Shadow Pilot | $1,500 (100% credited toward subscription) | Up to 250,000 shadow evaluations | Zero-retention /v1/shadow/ingest, 1 vertical pack (FMCSA / HIPAA / PCI), weekly risk & redaction report | Dedicated Zoom/Slack onboarding + custom rule tuning |
| Growth Gateway | $2,500 / mo | Up to 1,000,000 guarded requests/mo | Inline /v1/chat/completions & /api/v1/guard, all standard policy packs, SHA-256 ledger, NDJSON/CSV exports | Multi-tenant cloud gateway, 99.9% SLA, email/Slack support |
| Enterprise / Dedicated | $6,500+ / mo | 5,000,000+ requests/mo (custom burst) | Dedicated single-tenant Render/VPC deployment, PostgreSQL HA ledger, custom regex/schema rules, SIEM webhook streaming | 99.95% SLA, BAA / DPA execution, direct architect escalation |
Licensing & Early-Adopter Perks
Dual Licensing Model
 * Source-Available Evaluation & Internal Non-Production Use (BSL-1.1): Engineering and security teams may inspect, audit, and run validation suites locally or in non-production staging environments under the Business Source License 1.1.
 * Commercial Production License: Required for production traffic governance, commercial SaaS embedding, and managed compliance reporting. Includes full IP indemnification, custom policy pack authoring, and regulatory audit support.
Design-Partner & Early-Adopter Perks
 * 100% Pilot Fee Credit: Your full $1,500 30-day Shadow Pilot fee applies directly as a credit toward your first Growth or Enterprise subscription invoice.
 * Custom Domain Rule Authoring Included: Complimentary engineering of up to 5 bespoke entity redactors or business-logic guardrails (such as proprietary TMS load IDs, rate tables, or geofence rules) during onboarding.
 * Locked Founding-Partner Rate: Multi-year rate lock with zero overage penalties during your first 90 days of inline production cutover.
 * Audit-Ready Compliance Attestation Package: Cryptographic verification artifacts (HTML + JSON + SHA-256 chain proof) formatted for enterprise customer security questionnaires, shipper RFPs, and cyber-insurance underwriting.
Architected and maintained by Lucid Tech / Lucid-Truth-Audit · Contact: stickneycorey1@gmail.com
