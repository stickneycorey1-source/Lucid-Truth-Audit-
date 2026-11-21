# Lucid-Truth-Audit (LTA) Enterprise — v2.1

[[https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg]](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions)
[https://img.shields.io/badge/Pytest_Guardrail_Suite-61%2F61_Passing-10b981?style=flat&logo=pytest&logoColor=white]
[https://img.shields.io/badge/Live_Endpoint-Render_Active-38bdf8?style=flat&logo=fastapi&logoColor=white]
[https://img.shields.io/badge/Python-3.11-3776ab?style=flat&logo=python&logoColor=white]
[https://img.shields.io/badge/Pydantic-v2_Strict-e92063?style=flat&logo=pydantic&logoColor=white]
[https://img.shields.io/badge/Compliance-EU_AI_Act_%7C_ISO%2FIEC_42001_%7C_FMCSA_%7C_HIPAA_%7C_PCI-6366f1?style=flat]
[https://img.shields.io/badge/License-MIT-slate?style=flat]

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
