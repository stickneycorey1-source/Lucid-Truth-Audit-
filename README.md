# Lucid-Truth-Audit (v2.0.0)

**Deterministic AI Security, PII Redaction, and FMCSA Fleet Compliance Gateway**  
*Built by Corey Allen Stickney — Lucid Tech*

[![CI Status](https://img.shields.io/badge/CI-Pytest%20Automated-10b981?style=flat-square)](#automated-verification--ci)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.6-009688?style=flat-square)](https://fastapi.tiangolo.com/)
[![Pydantic](https://img.shields.io/badge/Pydantic-v2.10.4-e92063?style=flat-square)](https://docs.pydantic.dev/)
[![Python](https://img.shields.io/badge/Python-3.11-3776ab?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](./LICENSE)

**Live Portal & API:** `https://lucid-truth-audit.onrender.com`  
**Repository:** `https://github.com/stickneycorey1-source/Lucid-Truth-Audit`

---

## Overview

**Lucid-Truth-Audit** is a fail-closed, deterministic guardrail microservice built with **FastAPI** and **Pydantic v2** that sits in front of production LLM and AI-assisted logistics workflows. Rather than relying on another probabilistic model to police AI outputs, every request passes through strict schema contracts, obfuscation normalization, context-aware PII scrubbing, and regulatory rule checks—then writes sanitized metadata to an append-only, **SHA-256 hash-chained SQLite audit ledger**.

### Four Deterministic Defense Vectors

| Vector | Module | What It Enforces |
| :--- | :--- | :--- |
| **Vector 1: Prompt Injection & Obfuscation** | `app/normalizer.py`, `app/main.py` | Strips zero-width characters (`\u200b`–`\u200f`, `\u202a`–`\u202e`, `\ufeff`), normalizes NFKC compatibility forms, maps Cyrillic/Greek homoglyphs, and decodes both full-string and **embedded Base64/Hex payloads** inside prose. |
| **Vector 2: Context-Aware PII & Secret Redaction** | `app/main.py`, `app/schemas/logistics_guard.py` | Scrubs SSNs, Luhn-validated payment card numbers (PANs), API keys (`sk-...`, `AKIA...`), phone numbers, emails, and context-qualified driver CDL/DL numbers while **preserving operational PO, BOL, and trailer IDs** (e.g., `PO8492014`). |
| **Vector 3: Multi-Tenant Auth & Resilience** | `app/security.py`, `app/main.py` | Fail-closed `X-API-Key` validation using constant-time HMAC (`hmac.compare_digest`), multi-tenant keys with automatic `YYYY-MM-DD` trial expiration (`HTTP 403`), bounded sliding-window rate limiting (`HTTP 429`), repeating character/word and Shannon entropy flood blocking, and strict `extra="forbid"` schemas. |
| **Vector 4: FMCSA Fleet & Logistics Compliance** | `app/schemas/logistics_guard.py` | Deterministic enforcement of FMCSA 49 CFR § 395.3 shift rules (11h max drive, 14h duty window, 8h continuous drive / 30-min rest break), 60h/7-day and 70h/8-day cycle limits, 80,000 lb federal weight cap (with validated `XX-OSW-NNNN` oversize permit override), authorized geofenced waypoints, and indirect BOL prompt injection scanning. |

---

## Repository Structure

```text
Lucid-Truth-Audit/
├── app/
│   ├── main.py                      # FastAPI v2.0.0 entrypoint, security headers, Vectors 1–3, Ledger & CSV export
│   ├── security.py                  # Multi-tenant HMAC auth, auto-expiring 30-day pilot keys, bounded 429 limiter
│   ├── normalizer.py                # Shared zero-width, NFKC, homoglyph & embedded Base64/Hex normalizer
│   ├── ledger.py                    # Append-only SHA-256 hash-chained SQLite audit ledger
│   └── schemas/
│       └── logistics_guard.py       # Vector 4 FMCSA HOS/cycle, weight/permit, waypoint & BOL guardrails
├── static/
│   └── index.html                   # Zero-XSS browser portal (5 presets, CSV batch shadow runner, ledger viewer)
├── tests/
│   └── test_production_suite.py     # Automated Pytest suite covering auth, expiry, obfuscation, HOS, PII & ledger
├── .github/workflows/
│   └── ci_audit.yml                 # GitHub Actions CI compliance gate + artifact bundle upload
├── Dockerfile                       # Python 3.11-slim container bundling app/, static/, and tests/
├── render.yaml                      # Render Blueprint (Starter plan + 1GB persistent disk for SQLite ledger)
├── requirements.txt                 # Pinned runtime and test dependencies
├── LICENSE                          # MIT License
└── README.md                        # Project documentation
