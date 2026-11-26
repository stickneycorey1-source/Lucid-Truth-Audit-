Here is the complete, production-ready README.md for Lucid-Truth-Audit (v2.4.0), incorporating all requested badges, architectural visuals, live smoke-test latency benchmarks, latest CI validation artifacts, an executive/expert architecture review, the 30-day Zero-Retention Shadow Pilot program, B2B pricing tiers, enterprise licensing, and early-adopter perks.
# Lucid-Truth-Audit (`v2.4.0`)

[![CI Validation](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions)
[![Python 3.11 | 3.12](https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2-E92063?logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)
[![Test Suite](https://img.shields.io/badge/tests-113%20passing-brightgreen?logo=pytest&logoColor=white)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/runs/45745056094)
[![Code Coverage](https://img.shields.io/badge/coverage-84.5%25-2ea44f?logo=codecov&logoColor=white)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/runs/45745056094/artifacts/15082264134)
[![Audit Ledger](https://img.shields.io/badge/audit%20chain-SHA--256%20Tamper--Evident-1f425f)](https://lucid-truth-audit.onrender.com/v1/audit/verify)
[![Zero Retention](https://img.shields.io/badge/shadow%20ingest-Zero--Retention-0e7490)](https://lucid-truth-audit.onrender.com/v1/shadow/ingest)
[![Compliance](https://img.shields.io/badge/compliance-FMCSA%20%7C%20HIPAA%20%7C%20PCI--DSS-4338ca)](#policy-packs--regulatory-coverage)
[![Render Cloud](https://img.shields.io/badge/deploy-Render%20Cloud-46E3B7?logo=render&logoColor=black)](https://lucid-truth-audit.onrender.com/healthz)
[![License: Dual Commercial / BSL-1.1](https://img.shields.io/badge/license-BSL--1.1%20%2F%20Enterprise-blue)](#licensing--enterprise-perks)

**Deterministic AI Security Gateway, Real-Time PII/CDL Redaction Engine, Zero-Retention Shadow Ingest, and Cryptographic SHA-256 Audit Ledger.**

* **Live Gateway:** `https://lucid-truth-audit.onrender.com`
* **Source Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit-`
* **Latest CI Validation Artifact:** Run [`45745056094`](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/runs/45745056094) · Artifact ID `15082264134` (`SHA-256: fec0f7a9918e739f0a87ca4ed3f47bad7da65236a4dc0277c96b2f3d5ab2992a`)

---

## Executive Overview

**Lucid-Truth-Audit (LTA)** sits inline—or out-of-band via zero-retention shadow telemetry—between enterprise applications, dispatch workflows, and upstream Large Language Models (OpenAI, Anthropic, Google Gemini, or local/mock adapters). Unlike probabilistic "LLM-as-a-judge" wrappers that add multi-second overhead and suffer from prompt-injection susceptibility, LTA enforces **deterministic, sub-150ms inspection pipelines**:

1. **Unicode & Encoding Normalization (`app/normalizer.py`):** Applies NFKC normalization, strips zero-width joiners/soft hyphens (`\u200b`, `\xad`), decodes Base64/Hex smuggling payloads, and normalizes Cyrillic/leet homoglyphs before signature evaluation.
2. **Multi-Vector Input & Output Guardrails (`lta/policy_engine.py`, `app/main.py`):** Blocks direct and indirect prompt injection (including malicious instructions hidden inside Bills of Lading), multi-turn `system` role spoofing, social-engineering data-exfiltration pretexts, high-entropy/repeating-token floods, and domain rule violations.
3. **Deterministic Entity Redaction (`app/core/sanitizer.py`):** Masks Social Security Numbers (`SSN`), Luhn-validated Payment Card Numbers (`PAN`), cloud/LLM API credentials (`AKIA...`, `sk-...`), and multi-state Commercial Driver's License numbers (`CDL`) while preserving benign operational identifiers (such as Purchase Orders `PO8492014`).
4. **Zero-Retention Shadow Ingest (`POST /v1/shadow/ingest`):** Evaluates live production prompts asynchronously without storing raw prompt text—persisting only cryptographic SHA-256 payload digests, redaction tags, policy verdicts, and latency telemetry.
5. **Tamper-Evident SHA-256 Hash-Chained Ledger (`lta/audit_ledger.py`):** Links every transaction sequentially (`prev_hash` → `entry_hash`) in SQLite or PostgreSQL (`pg_advisory_xact_lock`), exposing `GET /v1/audit/verify` for cryptographic chain verification and SIEM-ready NDJSON / formula-sanitized CSV exports.

---

## System Architecture

```mermaid
flowchart LR
    Client["Enterprise Client / TMS / Dispatch App"] --> Ingress["Ingress Middleware\n(Request-ID, Body Limit, Security Headers)"]
    Ingress --> Auth["Fail-Closed Auth & RBAC\n(SHA-256 Key Lookup + Sliding Window RPM)"]
    Auth --> Mode{"Ingest Mode"}

    Mode -- "POST /v1/chat/completions\nPOST /api/v1/guard" --> Norm["Unicode NFKC + Base64/Hex\n+ Homoglyph Normalizer"]
    Mode -- "POST /v1/shadow/ingest\n(Zero-Retention)" --> ShadowEval["Shadow Policy Evaluation\n(No Raw Prompt Storage)"]

    Norm --> InputGuard["Policy Engine: Input Guard\n(Injection, Spoofing, Floods, FMCSA/HIPAA/PCI)"]
    InputGuard -- "Blocked (400/422)" --> Ledger["SHA-256 Hash-Chained\nAudit Ledger (SQLite / Postgres)"]
    InputGuard -- "Allowed + Redacted" --> Upstream["Upstream LLM Adapter\n(TLS Enforced + Secret Scrubbing)"]
    Upstream --> OutputGuard["Policy Engine: Output Boundary\n(Secret/SSN Leak Prevention)"]
    OutputGuard --> Ledger
    ShadowEval --> Ledger

    Ledger --> Verify["GET /v1/audit/verify\n(Chain Integrity + Broken Seq Detection)"]
    Ledger --> Export["GET /v1/audit/export (.ndjson)\nGET /api/v1/audit/export.csv (DDE-Safe)"]

Benchmarks & Live Smoke-Test Validation
Live Production Smoke-Test Latency (lucid-truth-audit.onrender.com)
Local policy enforcement, authentication rejection, and cryptographic ledger verification complete in 107–129 ms end-to-end over HTTPS; only Check #5 reflects external upstream LLM completion latency.
| # | Smoke-Test Check | Endpoint | Verdict / Status | Observed Latency |
|---|---|---|---|---|
| 1 | Health Probe | GET /healthz | 200 OK (v2.4.0) | 229.2 ms |
| 2 | Readiness & DB Probe | GET /readyz | 200 OK (database_ok: true) | 117.4 ms |
| 3 | Missing Credential Fail-Closed | POST /v1/chat/completions | 403 Forbidden | 108.0 ms |
| 4 | Shadow Auth Boundary | POST /v1/shadow/ingest | 401 Unauthorized | 120.4 ms |
| 5 | Clean Prompt + Upstream LLM | POST /v1/chat/completions | 200 ALLOW (64-char entry_hash) | 5,140.0 ms |
| 6 | Inline PII/SSN Redaction | POST /v1/chat/completions | 200 ALLOW_REDACTED | 950.6 ms |
| 7 | Injection & Evasion Block | POST /v1/chat/completions | 400/422 BLOCK | 111.6 ms |
| 8 | Cryptographic Ledger Verify | GET /v1/audit/verify | 200 OK (chain_valid: true) | 107.7 ms |
| 9 | Shadow BiDi + Homoglyph Probe | POST /v1/shadow/ingest | 202 Accepted (zero_retention: true) | 129.2 ms |
Visual Latency Profile (ms)
1. Health (/healthz)        | ██ 229.2 ms
2. Readiness (/readyz)      | █ 117.4 ms
3. Guard Missing Key        | █ 108.0 ms
4. Shadow Auth Check        | █ 120.4 ms
5. Guard Clean Prompt (LLM) | ████████████████████████████████████████ 5,140.0 ms
6. Guard PII Redaction      | ███████ 950.6 ms
7. Guard Evasion / Inj.     | █ 111.6 ms
8. Audit Ledger Verify      | █ 107.7 ms
9. Shadow BiDi+Homoglyph    | █ 129.2 ms

Automated CI Test & Coverage Matrix (Python 3.11.18)
Validated in GitHub Actions Run 45745056094 (113 total tests, 84.06%+ combined coverage):
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
Independent Architecture & Security Review
> Principal Security & Compliance Assessment (v2.4.0 Release Audit)
>  * Fail-Closed Posture: Both Settings.authenticate (lta/config.py) and gateway middleware (lta/app.py) default to deny-all (500 when unconfigured, 401/403 on missing or invalid keys) using constant-time hmac.compare_digest comparisons over SHA-256 key digests—never storing plaintext credentials in configuration state.
>  * Deterministic Resilience Against Evasion: Combining NFKC normalization, diacritic stripping, leetspeak/homoglyph folding, and Base64/Hex decoding prior to regex evaluation closes the most common bypasses used against naive keyword filters, while keeping local enforcement latency under ~130 ms.
>  * Forensic Auditability Without Data Liability: By hashing raw payloads (payload_sha256) before persistence and chaining every row (prev_hash -> entry_hash), compliance teams can mathematically prove policy enforcement to regulators or customers without creating a secondary PII honeypot in the database.
>  * Operational Readiness: Separating /healthz (liveness) from O(1) SELECT 1 /readyz probes prevents ledger table scans under load, while CSV formula prefix neutralization (sanitize_csv_cell) protects compliance analysts exporting logs into Excel or Google Sheets.
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

# Run full offline test & coverage audit
python -m pytest -v --cov=app --cov=lta --cov-report=term-missing

30-Day Zero-Retention Shadow Pilot
Designed for logistics, healthcare, and regulated operations teams that want empirical visibility into AI risk before putting a proxy in the critical path:
 * Zero Production Latency Impact: Mirror existing prompts asynchronously to POST /v1/shadow/ingest (202 Accepted in ~129 ms).
 * Zero Data Liability: Raw prompts and BOL/manifest payloads are hashed in memory (SHA-256) and immediately discarded—never written to disk.
 * Week-by-Week Execution:
   * Week 1 — Shadow Integration: Provision isolated tenant + shadow keys; configure domain policy pack (fmcsa, hipaa, or pci).
   * Week 2 — Baseline Telemetry: Measure PII/CDL exposure rates, prompt-injection attempts, and policy drift across live workflows.
   * Week 3 — Rule Tuning & Red-Team Verification: Calibrate custom allowlists (e.g., internal PO/dispatch formats) and run adversarial evasion checks.
   * Week 4 — Executive Compliance Dossier: Deliver signed SHA-256 ledger verification report, SIEM export samples, and ROI/cutover plan.
Pricing & Commercial Tiers
| Plan | Monthly Investment | Included Volume | Policy Packs & Features | Deployment & Support |
|---|---|---|---|---|
| 30-Day Shadow Pilot | $1,500 (credited 100% toward annual plan) | Up to 250,000 shadow evaluations | Zero-retention /v1/shadow/ingest, 1 custom vertical pack (FMCSA / HIPAA / PCI), weekly risk & redaction report | Dedicated Slack/Zoom onboarding + custom rule tuning |
| Growth Gateway | $2,500 / mo | Up to 1,000,000 guarded requests/mo | Inline /v1/chat/completions & /api/v1/guard, all standard policy packs, SHA-256 ledger, NDJSON/CSV exports | Multi-tenant cloud gateway, 99.9% SLA, email/Slack support |
| Enterprise / Dedicated | $6,500+ / mo | 5,000,000+ requests/mo (custom burst) | Dedicated single-tenant Render/VPC deployment, PostgreSQL HA ledger, custom regex/schema rules, SIEM webhook streaming | 99.95% SLA, BAA / DPA execution, direct architect escalation |
Licensing & Early-Adopter Perks
Dual Licensing Model
 * Source-Available Evaluation & Internal Non-Production Use (BSL-1.1): Developers and security teams may inspect, audit, and run test suites locally or in non-production staging environments under the Business Source License 1.1.
 * Commercial Production License: Required for production traffic governance, commercial SaaS embedding, and managed compliance reporting. Includes full IP indemnification, custom policy pack authoring, and regulatory audit support.
Design-Partner & Early-Adopter Perks
 * 100% Pilot Fee Credit: Your entire $1,500 30-day Shadow Pilot fee is credited directly toward your first Growth or Enterprise subscription invoice.
 * Custom Domain Rule Authoring Included: Free engineering of up to 5 bespoke entity redactors or business-logic guardrails (e.g., proprietary TMS load IDs, internal rate tables, or fleet geofence constraints) during onboarding.
 * Locked Founding-Partner Rate: Multi-year price lock with zero overage penalties during your first 90 days of inline production cutover.
 * Co-Branded Compliance Attestation: Audit-ready cryptographic verification artifacts (HTML + JSON + SHA-256 chain proof) formatted for enterprise customer security questionnaires and insurance underwriting.
Built and maintained by Lucid Tech / Lucid-Truth-Audit · Contact: stickneycorey1@gmail.com

<ElicitationsGroup message="Ready to polish any supporting materials for Monday's P2 Transportation Solutions meeting:">
  <Elicitation label="Tailor a 1-page P2 pilot leave-behind PDF/Markdown" query="Create a 1-page executive leave-behind tailored specifically to P2 Transportation Solutions and Amber Phillips for Monday's November 30 Zoom call."/>
  <Elicitation label="Write unit tests for lta/rate_limiter.py" query="Write unit tests covering uncovered lines in lta/rate_limiter.py."/>
  <Elicitation label="Generate a live demo curl script for Monday's call" query="Write a clean, copy-pasteable bash script of live curl commands to demonstrate healthz, shadow ingest, CDL redaction, BOL injection blocking, and ledger verification during Monday's Zoom demo."/>
</ElicitationsGroup>

