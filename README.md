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
```

---

## API Reference

All `/api/v1/*` endpoints require a valid `X-API-Key` header and return strict HTTP security headers (`Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`).

| Method | Endpoint | Auth | Purpose |
| :--- | :--- | :---: | :--- |
| `GET` | `/` | Public | Serves the Zero-XSS **Lucid-Truth-Audit Web Portal** (`static/index.html`) |
| `GET` | `/health` | Public | Returns service version, active vectors, and live SHA-256 ledger chain status |
| `POST` | `/api/v1/guard` | `X-API-Key` | Evaluates general LLM prompts & multi-turn messages (Vectors 1–3) |
| `POST` | `/api/v1/guard/logistics` | `X-API-Key` | Evaluates fleet dispatch, FMCSA HOS/cycle, weight/permit, waypoints & BOL notes (Vector 4) |
| `GET` | `/api/v1/audit/ledger` | `X-API-Key` | Returns tenant-scoped audit events and SHA-256 chain integrity verification |
| `GET` | `/api/v1/audit/export.csv` | `X-API-Key` | Streams a downloadable CSV compliance ledger for the authenticated tenant |

### Example Request (`POST /api/v1/guard/logistics`)

```bash
curl -X POST [https://lucid-truth-audit.onrender.com/api/v1/guard/logistics](https://lucid-truth-audit.onrender.com/api/v1/guard/logistics) \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-pilot-key" \
  -d '{
    "dispatch_id": "DISP-2026-9001",
    "driver_alias": "UNIT-MN-01",
    "vehicle_vin_hash": "9f86d081884c7d659a2feaa0c55ad015",
    "planned_drive_hours": 9.5,
    "on_duty_window_hours": 12.0,
    "continuous_drive_before_break_hours": 6.5,
    "rest_break_minutes": 30,
    "cycle_type": "70_8",
    "cycle_hours_used_before_shift": 40.0,
    "gross_vehicle_weight_lbs": 68500,
    "hazmat_class": "NONE",
    "bill_of_lading_notes": "Palletized freight PO8492014. Dock 4 check-in.",
    "dispatcher_summary": "Burnsville to Duluth I-35W haul.",
    "waypoints": [
      {"label": "Burnsville Hub", "latitude": 44.7677, "longitude": -93.2777, "is_authorized_facility": true},
      {"label": "Duluth Terminal", "latitude": 46.7867, "longitude": -92.1005, "is_authorized_facility": true}
    ]
  }'
```

---

## Local Quickstart & Configuration

### 1. Install Dependencies
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Multi-tenant API keys with optional automatic trial expiration (`YYYY-MM-DD` or `never`):
```bash
export LUCID_TENANT_KEYS="p2_pilot:p2-shadow-secret-2026:2026-12-22,lucid_admin:admin-secret-key:never"
export LUCID_RATE_LIMIT_MAX="60"
export LUCID_RATE_LIMIT_WINDOW_SEC="60"
export LUCID_LEDGER_DB_PATH="./lucid_audit_ledger.db"
```
*(Backward-compatible single-key mode via `LUCID_AUDIT_API_KEY` is also supported. If no key is configured, the server fails closed with `HTTP 503`.)*

### 3. Run the Server
```bash
uvicorn app.main:app --host 0.0.0.0 --port 10000 --reload
```
Open `http://localhost:10000/` for the interactive portal or `http://localhost:10000/docs` for Swagger UI.

---

## Automated Verification & CI

Run the full deterministic test suite and generate a self-contained HTML compliance report and JSON ledger:

```bash
pytest -v \
  --html=compliance_audit.html \
  --self-contained-html \
  --json-report \
  --json-report-file=audit_ledger.json
```

GitHub Actions (`.github/workflows/ci_audit.yml`) executes this suite on every push and pull request to `main` and publishes `compliance_audit.html` and `audit_ledger.json` as build artifacts.

---

## Deployment (Render Blueprint)

`render.yaml` provisions a Docker-backed **Render Starter** service with a **1 GB persistent disk** mounted at `/var/data` so the SHA-256 SQLite audit ledger persists across deploys and restarts:

1. Connect `stickneycorey1-source/Lucid-Truth-Audit` to Render using `render.yaml`.
2. Add `LUCID_TENANT_KEYS` in the Render **Environment** tab.
3. Verify live deployment at `GET /health` (`"version": "2.0.0"`, `"ledger_chain_valid": true`).

---

## 30-Day Shadow Pilot & Commercial Tiers

Lucid Tech offers a **5-spot Founding Partner Shadow Pilot** (standard **$4,800** 30-day pilot fee waived to **$0** for our first 5 fleet and safety-consulting partners in exchange for structured feedback):

| Tier | Pricing | Included Volume | Best For |
| :--- | :--- | :--- | :--- |
| **Founding Partner Pilot (5 Spots)** | **$0** *(List: $4,800)* | 25,000 checks / 30 days | First 5 fleet & consulting partners (zero live TMS disruption) |
| **Standard Shadow Pilot (Spot 6+)** | **$4,800** *(one-time)* | 25,000 checks / 30 days | Paid evaluations (100% credited to annual plan) |
| **Fleet Starter** | **$599 / mo** | 10,000 checks / mo | Single regional carriers & boutique safety consultants |
| **Production Gateway** | **$1,800 / mo** *($1,350/mo Founding Lock)* | 100,000 checks / mo | Mid-market fleets & TMS/dispatch AI integrations |
| **Enterprise Defense** | **$6,400 / mo** | 1,000,000+ checks / mo | VPC / on-prem deployments, custom vectors & compliance binder |

*Overage checks bill at $5 per 1,000 evaluations. Annual billing includes 2 months free.*

---

## Regulatory Alignment Notice

Control mappings align with **FMCSA 49 CFR § 395.3** (property-carrying Hours of Service bounds), **EU AI Act (Regulation (EU) 2024/1689)** risk-management and logging expectations, and **ISO/IEC 42001** governance practices. This software is a deterministic technical control and does not constitute formal legal certification or ELD replacement.

---

## License

Released under the [MIT License](./LICENSE). Copyright © 2026 Corey Allen Stickney (Lucid Tech).