# Lucid-Truth-Audit (`v2.4.1`) · API Reference

## Authentication & Headers

* **API Key Auth:** Pass a configured tenant or admin key via `X-API-Key: <key>` or `Authorization: Bearer <key>`.
* **Optional Override Headers (`admin` role required):**
  * `X-LTA-Policy`: Override the tenant's default policy pack for a single request.
  * `X-LTA-Provider`: Override the tenant's default upstream provider for a single request.
* **Response Security Headers:** Every response includes `X-Request-ID`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`.

---

## Endpoints

* **`GET /health` & `GET /healthz`:** Public liveness check returning `status`, `version`, and `policies_loaded`.
* **`GET /readyz`:** Public readiness check verifying `AuditLedger.ping()`, configured tenants, and loaded policy packs (`503` if not ready).
* **`GET /v1/policies`:** Authenticated endpoint returning `active_tenant`, `active_policy`, and `available_policies`.
* **`POST /v1/chat/completions`:** OpenAI-compatible chat completion proxy (`messages` array with `role` in `system | user | assistant`, optional `model`, `temperature`, `max_tokens`, `metadata`; `extra="forbid"`). Returns `object: "chat.completion"`, `choices`, `lta_audit`, and top-level audit/redaction fields.
* **`POST /api/v1/guard`:** Single-input guard endpoint accepting `model_input` and optional `metadata` (`extra="forbid"`). Runs the shared pipeline and returns `status`, `allowed`, and pipeline result/audit metadata.
* **`GET /v1/audit/verify` (`admin` only):** Walks the SHA-256 hash chain (`prev_hash` -> `entry_hash`) and returns `chain_valid`, `total_records`, and `first_broken_seq_id`.
* **`GET /v1/audit/export` (`admin` only):** Returns SIEM-ready NDJSON (`application/x-ndjson`) supporting optional `tenant_id` and `limit` (`1`–`5000`, default `500`).
* **`GET /metrics` (`admin` only):** Returns Prometheus text metrics (`text/plain; version=0.0.4`).
