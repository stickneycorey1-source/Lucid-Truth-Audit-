# Lucid-Truth-Audit

**Deterministic AI Security Gateway · PII Redaction · Evidence Chain · FMCSA Fleet Compliance**

Built by Corey Allen Stickney — Lucid Tech

[![CI](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-2.0.3-0ea5e9?style=flat-square)](#)
[![Python](https://img.shields.io/badge/Python-3.11-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Pydantic](https://img.shields.io/badge/Pydantic-v2-e92063?style=flat-square)](https://docs.pydantic.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](./LICENSE)
[![Security](https://img.shields.io/badge/Security-Fail--Closed-10b981?style=flat-square)](#security-posture)
[![Audit](https://img.shields.io/badge/Audit-SHA--256%20Hash%20Chain-8b5cf6?style=flat-square)](#audit-ledger--evidence-chain)

**Live Portal:** [https://lucid-truth-audit.onrender.com](https://lucid-truth-audit.onrender.com)  
**Repository:** [stickneycorey1-source/Lucid-Truth-Audit-](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-)

---

## Overview

Lucid-Truth-Audit is a **fail-closed, deterministic** guardrail microservice that sits in front of production LLM and AI-assisted logistics workflows. Every request is evaluated through strict Pydantic v2 schemas, obfuscation-resistant normalization, context-aware PII/secret redaction, and regulatory rule checks — then recorded in an append-only **SHA-256 hash-chained SQLite audit ledger**.

No probabilistic “AI judge” is used. Decisions are repeatable, auditable, and fast.

### Four Defense Vectors

| Vector | What it enforces |
| :--- | :--- |
| **1 · Prompt Injection & Obfuscation** | Zero-width / bidi stripping, NFKC normalization, homoglyph mapping, embedded Base64 & Hex decoding, multi-turn role-spoof detection |
| **2 · Context-Aware PII & Secrets** | SSN, Luhn-validated PAN, API secrets (`sk-…`, `AKIA…`), phone, email, multi-state CDL/DL — while preserving operational PO / BOL / trailer IDs |
| **3 · Auth, Tenancy & Resilience** | Constant-time HMAC key validation, multi-tenant keys with optional trial expiry, sliding-window rate limiting, entropy / flood blocking, `extra="forbid"` schemas |
| **4 · FMCSA Fleet Compliance** | 49 CFR § 395.3 HOS bounds, 60/7 & 70/8 cycle accounting, 80 000 lb weight cap + validated oversize permits, authorized waypoints, BOL injection scanning |

---

## Architecture Highlights

- **Fail-closed by default** — missing or invalid keys → `401` / `403` / `503`; malformed payloads never reach downstream models
- **Tenant isolation** — ledger and evidence records are scoped by authenticated tenant
- **Append-only hash chain** — every audit event and evidence record carries a SHA-256 link to the previous entry
- **Zero-XSS portal** — dark-themed static frontend with CSP, presets, and live ledger viewer
- **CSV formula injection protection** — exported ledgers neutralize DDE / formula prefixes

---

## Repository Layout

```text
Lucid-Truth-Audit-/
├── app/
│   ├── main.py                 # FastAPI entrypoint, Vectors 1–3, evidence + ledger APIs
│   ├── security.py             # Multi-tenant HMAC auth, rate limiting, trial expiry
│   ├── normalizer.py           # Shared obfuscation / encoding normalizer
│   ├── ledger.py               # SHA-256 hash-chained SQLite audit ledger
│   ├── evidence_chain.py       # Tenant-isolated evidence record store
│   └── schemas/
│       └── logistics_guard.py  # Vector 4 FMCSA / weight / BOL guardrails
├── static/
│   └── index.html              # Zero-XSS browser portal
├── tests/
│   ├── test_production_suite.py
│   ├── test_evidence_chain.py
│   └── test_vector4_logistics.py
├── .github/workflows/
│   └── ci.yml                  # Pytest + HTML/JSON compliance artifacts
├── Dockerfile
├── render.yaml
├── requirements.txt
└── README.md