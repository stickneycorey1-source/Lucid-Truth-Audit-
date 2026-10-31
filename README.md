# Stickney-Audit-Mandate (Lucid Truth Audit)

A zero-trust AI security middleware and Red Team compliance engine, architected by Corey Allen Stickney (Dr. Lucid). 

**Proprietary Asset**: All rights reserved under commercial copyright.

## 🛡️ Architectural Overview
Stickney-Audit-Mandate is a high-performance, edge-deployed security guardrail designed to sanitize and audit generative AI payloads. Hosted via Render and built on a lightweight FastAPI framework, the system acts as an impenetrable gateway between frontend user inputs and external LLM infrastructure (currently optimized for Gemini 3.8 Flash). 

By evaluating payloads heuristically before AI execution, it guarantees that sensitive PII and prompt injection attacks are neutralized in milliseconds.

## ✨ Core Features
- **Zero-Trust Authentication:** Enforces strict `x-api-key` headers (`lucid-prop-key-2026`) to protect the Render endpoint from unauthorized requests and brute-force token draining.
- **Pydantic v2 Schema Validation:** Utilizes strict, type-safe data modeling to mathematically validate and sanitize every inbound `GuardRequest`.
- **Persistent SQLite Threat Ledger:** Automatically initializes `lucid_audit.db` to intercept and permanently record every blocked threat (timestamp, risk level, raw malicious input) for NIST/OWASP compliance and CISO auditing.
- **Continuous Integration (CI/CD):** A zero-tolerance automated testing pipeline powered by GitHub Actions and `pytest` to guarantee security reliability and prevent regressions on every deployment.

## 💼 Enterprise Value & ROI
- **Zero-Token Waste:** Malicious payloads (prompt injections, jailbreaks) are killed instantly at the middleware layer. The enterprise pays zero generative API compute costs for blocked attacks.
- **Catastrophic Liability Avoidance:** Prevents PII (SSNs, PHI, financial data) from ever reaching external LLM servers, neutralizing multi-million dollar compliance violations.
- **Latency Optimization:** Safe traffic passes through with near-zero latency, while threats are dropped instantly at the API gateway.

## 🚀 Quickstart

**1. Install Dependencies**
```bash
pip install fastapi uvicorn pydantic pytest requests
