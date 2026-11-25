# Lucid-Truth-Audit (LTA) · Enterprise AI Security & Compliance Gateway

[![Test Suite](https://img.shields.io/badge/tests-96%2F96%20passing-brightgreen.svg)](#verification--ci-metrics)
[![Code Coverage](https://img.shields.io/badge/coverage-80.63%25-brightgreen.svg)](#verification--ci-metrics)
[![Live Smoke Test](https://img.shields.io/badge/live%20smoke%20test-100%25%20(8%2F8)-brightgreen.svg)](#live-production-smoke-test-benchmarks)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.165%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063.svg)](https://docs.pydantic.dev/)
[![Zero-Retention](https://img.shields.io/badge/zero--retention-verified-success.svg)](#documentation--runbooks)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%7C%20Commercial-blue.svg)](#licensing)

**Lucid-Truth-Audit (LTA)** is a hardened, drop-in OpenAI-compatible enterprise AI security, PII/PHI redaction, and regulatory compliance gateway (`v2.4.1`). It sits between client applications and upstream foundation models (`OpenAI`, `Azure OpenAI`, `Anthropic`, `Google Gemini`, `vLLM`, `Ollama`) to sanitize inputs, enforce domain-specific YAML policy packs, block prompt injection and multi-turn system spoofing, redact sensitive entities in real time, and record tamper-evident SHA-256 hash-chained audit logs with zero raw-prompt retention.

* **Live Production Deployment:** `https://lucid-truth-audit.onrender.com`
* **Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit-`

---

## Core Capabilities

* **OpenAI-Compatible Proxy & Legacy Guard API:** Drop-in `POST /v1/chat/completions` (`object: "chat.completion"`, `choices`, and `lta_audit` metadata) alongside `POST /api/v1/guard` for single-turn policy evaluation.
* **Defense-in-Depth Input & Output Guardrails:**
  * NFKC Unicode normalization, zero-width/BiDi override stripping (`\u202e`), homoglyph detection, and Base64/Hex/leetspeak payload inspection.
  * Multi-turn conversation scanning to block cross-turn split injections, unauthorized `system` role spoofing, and poisoned `assistant` turns.
  * High-entropy gibberish, repeating-character, and repeating-word flood mitigation.
  * Output boundary enforcement preventing system prompt leaks, raw SSNs, and API credentials (`sk-...`, `ghp_...`, `AKIA...`, `AIza...`) from exiting the gateway.
* **Domain Regulatory Policy Packs:**
  * **Healthcare (`healthcare_hipaa`):** Redacts Medical Record Numbers (`MRN`), SSNs, and protected patient identifiers.
  * **Finance (`finance_pci`):** Luhn-validated PAN card redaction while preserving benign reference IDs, plus wire-threshold metadata checks.
  * **Logistics (`logistics_fmcsa`):** Multi-state Commercial Driver's License (`CDL` / `DL`) redaction while preserving Purchase Orders (`PO`), 60/7 and 70/8 Hours-of-Service (`HOS`) validation, gross vehicle weight checks, and waypoint-hijack defense.
  * **General Enterprise (`general_enterprise`):** Baseline PII redaction, social-engineering pretext blocking, and strict schema validation.
* **Tenant Isolation & Resilience:**
  * Fail-closed authentication (`X-API-Key` or `Authorization: Bearer`) with role-based access control (`admin` vs. tenant keys; non-admin policy/provider override attempts rejected with `403`).
  * Per-tenant sliding-window rate limiter (`429 Too Many Requests` with `X-RateLimit-Remaining`) backed by atomic Redis Lua scripts with resilient in-memory fallback.
  * Strict Pydantic v2 validation (`extra="forbid"`, `NaN`/non-numeric metadata rejection) and `256 KiB` (`LTA_MAX_BODY_BYTES`) streaming body size enforcement (`413`).
* **Cryptographic Hash-Chained Audit Ledger:**
  * Append-only SQLite / PostgreSQL (`pg_advisory_xact_lock`) audit log chaining every event via SHA-256 (`prev_hash` -> `entry_hash`) without storing raw prompt text (`payload_sha256` digest only).
  * Built-in chain verification (`GET /v1/audit/verify`), SIEM-ready
