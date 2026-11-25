# Lucid-Truth-Audit (`v2.4.1`) · System Architecture

## Overview

**Lucid-Truth-Audit (LTA)** is a FastAPI and Pydantic v2 AI security, redaction, and regulatory compliance gateway sitting between client workloads and upstream LLM providers (`OpenAI`, `Azure OpenAI`, `Anthropic`, `Google Gemini`, `vLLM`, `Ollama`, or `mock` / simulated fallback).

```text
Client / App
   │
   ▼
[Middleware]  X-Request-ID, Security Headers, 256 KiB Body Limit (413)
   │
   ▼
[Auth & RBAC] X-API-Key / Bearer -> TenantConfig -> SlidingWindowRateLimiter (429)
   │
   ▼
[Pipeline]    Admin Override Check -> Policy Pack Lookup -> System-Role Guard
   │            -> Combined & Per-Turn Input Sanitization/Policy Evaluation
   ▼
[Upstream]    call_upstream() -> Output Boundary & Redaction Evaluation
   │
   ▼
[Audit Ledger] SHA-256 Hash Chain (payload_sha256, prev_hash -> entry_hash) + Metrics
