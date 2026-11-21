# Lucid-Truth-Audit (LTA) Enterprise — v2.1

[[https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg]](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions)
[[https://img.shields.io/static/v1?label=Pytest+Suite&message=61/61+Passing&color=10b981&logo=pytest&logoColor=white]](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions)
[[https://img.shields.io/static/v1?label=Live+API&message=Render+Active&color=38bdf8&logo=fastapi&logoColor=white]](https://lucid-truth-audit.onrender.com/docs)
[https://img.shields.io/static/v1?label=Python&message=3.11&color=3776ab&logo=python&logoColor=white]
[https://img.shields.io/static/v1?label=Pydantic&message=v2+Strict&color=e92063&logo=pydantic&logoColor=white]
[https://img.shields.io/static/v1?label=Compliance&message=EU+AI+Act+%7C+ISO+42001+%7C+FMCSA+%7C+HIPAA+%7C+PCI&color=6366f1]
[https://img.shields.io/static/v1?label=Local+p95&message=3.67ms&color=0ea5e9]
[https://img.shields.io/static/v1?label=License&message=MIT&color=475569]

**Drop-In, Provider-Agnostic AI Security, PII Redaction, and Tamper-Evident Compliance Gateway for Production LLM Workflows.**

Lucid-Truth-Audit (LTA) sits in front of any LLM provider (OpenAI, Anthropic, Google Gemini, Azure OpenAI, vLLM, or Ollama) as an OpenAI-compatible proxy (`/v1/chat/completions`) and legacy guardrail API (`/api/v1/guard`). Every request passes through fail-closed multi-tenant authentication, RBAC policy isolation, NFKC/homoglyph/encoding canonicalization, config-driven YAML industry policy packs, strict Pydantic v2 validation, and a SHA-256 hash-chained audit ledger.

* **Live Interactive API & Swagger Docs:** [https://lucid-truth-audit.onrender.com/docs](https://lucid-truth-audit.onrender.com/docs)
* **GitHub Repository:** [https://github.com/stickneycorey1-source/Lucid-Truth-Audit-](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-)

---

## One-Line Drop-In Integration (Any OpenAI SDK App)

Point your existing OpenAI SDK client (or LangChain, LlamaIndex, Vercel AI SDK) at LTA—no application rewrite required:

```python
from openai import OpenAI

client = OpenAI(
    base_url="[https://lucid-truth-audit.onrender.com/v1](https://lucid-truth-audit.onrender.com/v1)",
    api_key="YOUR_TENANT_LTA_KEY",
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Summarize today's dispatch manifest."}],
)
```

---

## Defense-in-Depth Architecture (v2.1 Hardened)

```text
Incoming Request ─► [1. Fail-Closed Multi-Tenant Auth + SHA-256 Hashed Keys + RBAC]
                      ├─► Missing / Invalid Key ──────────────────► 403 Forbidden
                      ├─► Non-Admin Policy/Provider Override ─────► 403 Forbidden
                      ├─► Sliding-Window Rate Limit (Mem/Redis) ──► 429 Too Many Requests
                      ▼
                    [2. Strict Input Schema: Pydantic v2 (extra="forbid")]
                      ├─► Unexpected Fields / Invalid Shapes ─────► 422 Unprocessable Entity
                      ▼
                    [3. Canonicalization & Multi-Turn Policy Engine (YAML Packs)]
                      ├─► NFKC / Zero-Width / Cyrillic / Whitespace / URL / Base64 / Hex
                      ├─► Split Multi-Turn & System-Role Spoofing ─► 400 Bad Request
                      ├─► Floods (Char / Word / High-Entropy) ────► 400 Bad Request
                      ├─► Industry Rules (FMCSA / HIPAA / PCI) ───► 422 Unprocessable Entity
                      ├─► PII / PHI / PCI Redaction (Luhn PAN, SSN, MRN, CDL, Secrets)
                      ▼
                    [4. Provider-Agnostic Upstream Router]
                      ├─► OpenAI | Anthropic | Gemini | Azure | Ollama | vLLM | Mock
                      ├─► Upstream HTTP Failure ──────────────────► 502 Bad Gateway
                      ▼
                    [5. Output Boundary Validator + Tamper-Evident Audit Ledger]
                      ├─► System Prompt / SSN / Secret Leak ──────► 500 Blocked
                      └─► Clean Response ─────────────────────────► 200 OK + SHA-256 Hash-Chained Record
```

---

## Industry YAML Policy Packs (`policy_packs/`)

Onboard any vertical without changing Python code:

| Policy Pack | Target Vertical | Key Controls & Regulatory Alignment |
| :--- | :--- | :--- |
| `general_enterprise` | General SaaS / Enterprise | Prompt-injection defense, social-engineering blocks, PII/PAN/secret redaction, OWASP LLM Top 10, NIST AI RMF 1.0, EU AI Act, ISO/IEC 42001 |
| `logistics_fmcsa` | Trucking & Dispatch | FMCSA HOS drive/duty/break limits, 80,000 lb weight cap, Bill of Lading indirect injection & waypoint-hijack defense, CDL/driver PII redaction |
| `healthcare_hipaa` | Clinical & Health Tech | MRN/SSN/PHI redaction, bulk patient-record export blocking, unsupervised controlled-prescription blocks, HIPAA |
| `finance_pci` | Banking & FinTech | Luhn PAN & bank account/routing redaction, unapproved wire caps, dual-control bypass blocking, PCI-DSS v4.0 & GLBA |

---

## API Endpoints

| Method & Path | Access | Purpose |
| :--- | :--- | :--- |
| `POST /v1/chat/completions` | Tenant Key | Drop-in OpenAI-compatible guarded chat proxy |
| `POST /api/v1/guard` | Tenant Key | Backward-compatible single-prompt LTA guardrail endpoint |
| `GET /v1/policies` | Tenant Key | Lists loaded YAML policy packs and active tenant policy |
| `GET /v1/audit/verify` | Admin Key | Cryptographically verifies the entire SHA-256 audit hash chain |
| `GET /v1/audit/export` | Admin Key | Exports SIEM-ready JSONL audit logs (raw prompts never stored) |
| `GET /metrics` | Public / Internal | Prometheus scrape endpoint (request counts, block vectors, latency quantiles) |
| `GET /healthz` & `/readyz` | Public / Internal | Container liveness and readiness probes (checks hash-chain integrity) |

---

## Verified Test Suite & Local Performance

* **Automated CI Suite:** **61 / 61 tests passing** via GitHub Actions (`pytest`), covering core gateway injection/encoding defense, PII/social-engineering redaction, sliding-window rate limiting and flood defense, FMCSA logistics guardrails, multi-industry YAML policy packs, RBAC override enforcement, split multi-turn injection defense, and cryptographic audit-chain tamper detection.
* **Local Gateway Overhead (200-request benchmark, `logistics_fmcsa` + PII redaction + SQLite SHA-256 hash chain):** **295.4 req/s** | **3.31 ms p50** | **3.67 ms p95** | **4.36 ms p99** | **200/200 valid hash-chain records**.

---

## Self-Hosted VPC Deployment (Docker Compose)

Run LTA inside your own VPC backed by PostgreSQL (with transactional `pg_advisory_xact_lock` hash-chain serialization) and Redis distributed rate limiting:

```bash
cp .env.example .env
# Edit .env with tenant API keys, Postgres credentials, and upstream provider keys
docker compose up -d --build
```

Run tests locally:

```bash
python -m pytest -v
```
