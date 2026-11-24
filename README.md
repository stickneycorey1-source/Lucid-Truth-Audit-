# Lucid-Truth-Audit (LTA) — Enterprise Gateway v2.3 Hardened

[![Lucid Truth Audit CI](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions)
![Pytest Suite](https://img.shields.io/badge/Pytest_Suite-93%2F93_Passing-10b981?style=flat&logo=pytest&logoColor=white)
![Coverage](https://img.shields.io/badge/Coverage-80.25%25-10b981?style=flat&logo=codecov&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-3776ab?style=flat&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Validated-2496ed?style=flat&logo=docker&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2_Strict-e92063?style=flat&logo=pydantic&logoColor=white)
![Compliance](https://img.shields.io/badge/Compliance-EU_AI_Act_%7C_ISO%2FIEC_42001_%7C_FMCSA-6366f1?style=flat)
![License](https://img.shields.io/badge/License-Proprietary_Evaluation_Only-amber?style=flat)

**Deterministic AI Security, Schema Guardrails, Hash-Chained Audit Logging, and Pre-Emptive Policy Enforcement for LLM APIs.**

Lucid-Truth-Audit (LTA) / Stickney-Audit-Mandate is a pre-emptive FastAPI and Pydantic v2 (`extra="forbid"`) security and compliance gateway. It sits ahead of LLM calls through an OpenAI-compatible proxy and policy-enforcement API.

* **Live Interactive API & Swagger Docs:** https://lucid-truth-audit.onrender.com/docs
* **GitHub Repository:** https://github.com/stickneycorey1-source/Lucid-Truth-Audit-
* **License:** Proprietary (All Rights Reserved — Evaluation Only)

---

## Validation Status

| Check | Result |
|---|---|
| Test suite | **93/93 passing** |
| Coverage | **80.25%** |
| Python | **3.11 and 3.12** |
| Docker build | **Passing** |
| Docker Compose | **Passing** |
| Dependency audit | **Passing** |
| Container health check | **Passing** |
| Audit-chain, PII, RBAC, injection, resilience, and policy tests | **Passing** |

The GitHub Actions workflow verifies tests, branch coverage, dependency security, Docker Compose configuration, Docker image building, and application health after startup.

---

## Verified Metrics & Benchmark Snapshot

* **Current CI Suite:** **93/93 tests passing** on Python 3.11 and 3.12, with **0 failures** and **0 errors**.
* **Coverage:** **80.25%** across `app` and `lta`.
* **Security Coverage:** prompt injection, obfuscation, PII redaction, social engineering, resilience, tenant isolation, RBAC, strict schemas, evidence-chain integrity, and policy packs.
* **Deployment Coverage:** Docker build, Docker Compose rendering, persistent storage configuration, health checks, and container startup validation.
* **Local Gateway Benchmark:** retain only benchmark values verified from the current host environment.

---

## Defense-in-Depth Architecture

```text
Incoming Request
  ├─► [1] Authentication and tenant isolation
  │     └─► Missing / invalid credentials ─► Reject
  │
  ├─► [2] Strict Pydantic payload validation
  │     └─► Unexpected fields / invalid shape ─► 422
  │
  ├─► [3] Canonicalization and anomaly detection
  │     └─► Injection / obfuscation / flood ─► 400 or 429
  │
  ├─► [4] YAML policy enforcement
  │     └─► Enterprise / FMCSA / HIPAA / PCI policies
  │
  ├─► [5] Output validation and audit chain
        └─► PII / secret / instruction leakage ─► Block or redact