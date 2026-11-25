# Lucid-Truth-Audit (LTA) · Enterprise AI Security & Compliance Gateway

[![Version](https://img.shields.io/badge/version-2.4.1-blue.svg)](https://lucid-truth-audit.onrender.com/healthz)
[![Smoke Test](https://img.shields.io/badge/live%20smoke%20test-9%2F9%20(100%25)-brightgreen.svg)](https://lucid-truth-audit.onrender.com/readyz)
[![Unit Suite](https://img.shields.io/badge/pytest-101%2F101%20passed-success.svg)](#validation--test-suite-results)
[![Shadow Coverage](https://img.shields.io/badge/shadow.py-97%25%20coverage-informational.svg)](#validation--test-suite-results)
[![Zero Retention](https://img.shields.io/badge/shadow%20ingest-zero%20retention-indigo.svg)](#zero-retention-shadow-ingest)
[![Ledger](https://img.shields.io/badge/audit%20ledger-SHA--256%20hash--chain-slate.svg)](#cryptographic-audit-ledger)
[![License](https://img.shields.io/badge/license-Commercial%20%2F%20Proprietary-critical.svg)](#license)

**Lucid-Truth-Audit (LTA)** is a FastAPI and Pydantic v2 enterprise AI security, policy enforcement, PII/secret redaction, and cryptographic audit gateway. It sits in front of upstream LLM providers (such as Google Gemini) and supports zero-retention shadow telemetry ingestion for enterprise evaluation and 30-day pilot deployments.

* **Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit`
* **Live Deployment:** `https://lucid-truth-audit.onrender.com`
* **Latest Verified Smoke Run:** `2026-11-25 19:41:15 UTC` — **9/9 checks passed (100.0%)**
* **Latest Ledger / SHA-256 Reference:** `5c303fae2ce8e0c4e581e09f3d1445a3e6a67f77ad4d473d94df6efc10dc580d`
* **Latest Validation Artifact:** `lucid-truth-audit-3.11-validation` (`ID 15059735258`, SHA-256 `c56b18ca0644b8113bbae4f93d5a5ae000fc1c467733565fb60008292d001e20`)

---

## Architecture & Capabilities

* **Ingress & Strict Schema Validation (`lta/app.py`):**
  * Enforces payload size caps (`LTA_MAX_BODY_BYTES`, default `262144` bytes / `256 KiB` -> HTTP `413`), hardened response headers (`X-Request-ID`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`), and strict Pydantic v2 validation (`extra="forbid"`) with finite-float metadata checks.
* **Multi-Turn Policy & Evasion Engine (`lta/policy_engine.py` / `app/core/sanitizer.py`):**
  * Normalizes and inspects prompts and responses against prompt injection, Unicode BiDi/homoglyph evasion, system-role spoofing, anomaly floods, and sensitive data leakage.
  * Redacts PII and secrets (SSNs, Luhn PANs, multi-state CDLs, API keys/tokens) while preserving benign identifiers/POs and blocking raw secret/PII exfiltration.
* **Zero-Retention Shadow Ingest (`POST /v1/shadow/ingest`):**
  * Authenticates shadow ingest requests via `Authorization: Bearer <LTA_SHADOW_KEY>` using constant-time comparison (`hmac.compare_digest`), computes a 64-character `input_sha256` digest, records zero-retention audit metadata (`zero_retention: true`, `audit_id`, `input_sha256`), and never stores or echoes raw prompts.
* **Cryptographic Audit Ledger (`lta/audit_ledger.py`):**
  * Appends `ALLOW`, `ALLOW_REDACTED`, and `BLOCK` events into a tamper-evident SHA-256 hash chain verifiable via `GET /v1/audit/verify` and exportable as NDJSON via `GET /v1/audit/export`.
* **Tenant Auth, Rate Limiting & Telemetry (`lta/config.py`, `lta/rate_limiter.py`, `lta/metrics.py`):**
  * Enforces tenant/admin credentials (`X-API-Key` / `Authorization: Bearer`), sliding-window RPM rate limits (`429` + `X-RateLimit-Remaining`), and Prometheus metrics exposition (`GET /metrics`).

---

## Repository Structure & Documentation Map

```text
Lucid-Truth-Audit/
├── README.md                          # Gateway overview, env vars, API reference, benchmarks, test & pilot records
├── lta/
│   ├── app.py                         # FastAPI gateway, ingress middleware, auth guards, /v1/shadow/ingest & audit routes
│   ├── audit_ledger.py                # Tamper-evident SHA-256 hash-chained audit ledger & NDJSON export
│   ├── config.py                      # Environment & tenant configuration loader (Settings.from_env)
│   ├── metrics.py                     # Prometheus metrics registry
│   ├── policy_engine.py               # Input/output guardrails, PII/secret redaction & evasion detection
│   ├── providers.py                   # Upstream LLM adapters (Gemini, OpenAI, Anthropic, Mock)
│   └── rate_limiter.py                # Sliding-window per-tenant rate limiter
├── app/
│   ├── api/shadow.py                  # Shadow router schemas, tenant key verification & ZeroRetentionAuditRecord
│   └── core/sanitizer.py              # Unicode BiDi, NFKC & homoglyph sanitizer
├── scripts/
│   └── run_smoketest.py               # 9-check live smoke test + Chart.js HTML compliance report generator
├── tests/
│   ├── test_audit.py                  # Prompt injection, encoding evasion, auth & redaction tests
│   ├── test_audit_ledger_and_providers.py # Hash chain tamper detection, JSONL export & upstream TLS checks
│   ├── test_deployment_validation.py  # Dockerfile, Render, Compose & CI validation checks
│   ├── test_enterprise_gateway.py     # RBAC, policy packs (PCI/HIPAA/FMCSA), rate limits & multi-turn spoofing
│   ├── test_evidence_chain.py         # Evidence creation, tenant isolation, persistence & tamper detection
│   ├── test_production_suite.py       # Hardened obfuscation, CDL redaction, HOS/weight & CSV formula checks
│   ├── test_shadow_ingest.py          # Shadow ingest auth & zero-retention audit tests
│   └── test_vector2_pii.py & test_vector4_logistics.py # PII pretext/Luhn & FMCSA dispatch/BOL tests
├── reports/                           # CI validation & coverage artifacts (uploaded in validation run)
└── .github/workflows/
    └── smoketest.yml                  # Automated CI live verification & HTML report artifact upload
