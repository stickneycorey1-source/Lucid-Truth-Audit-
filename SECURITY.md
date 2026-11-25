# Security Policy & Architecture Posture

## Supported Versions

| Version | Status | Support & Security Updates |
| :--- | :--- | :--- |
| `2.4.x` | **Active** | Full security patches, policy pack updates, and CI verification |
| `< 2.4.0` | Unsupported | Upgrade to `2.4.1` or later |

---

## Security & Zero-Retention Guarantees

* **Zero Raw-Prompt Persistence:** `lta/audit_ledger.py` computes a SHA-256 digest (`payload_sha256`) of incoming content in memory and persists only cryptographic hashes, timestamps, tenant IDs, policy packs, redaction category labels (e.g., `["MRN", "SSN"]`), and latency telemetry. Raw prompts and raw PII/PHI never touch disk.
* **Tamper-Evident SHA-256 Hash Chain:** Every audit record links to `prev_hash` (starting from `GENESIS_HASH = "0" * 64`) and is serialized under a database transaction lock (`pg_advisory_xact_lock` on PostgreSQL; mutex lock on SQLite). Any modification or deletion breaks `/v1/audit/verify`.
* **Fail-Closed Authentication & RBAC:** Requests without a valid configured tenant key are rejected (`403` / `500` when keyring is empty). Non-admin keys cannot override `X-LTA-Policy` or `X-LTA-Provider` (`403`) and cannot access `/v1/audit/verify`, `/v1/audit/export`, or `/metrics`.
* **Transport & Payload Hardening:**
  * Non-local upstream provider URLs must use `https://` (`validate_upstream_url`).
  * Streaming request body limits enforce `LTA_MAX_BODY_BYTES` (`256 KiB` default, `413` on overflow).
  * Upstream error messages scrub bearer tokens and API key patterns (`sk-...`, `ghp_...`, `AKIA...`, `AIza...`) before returning `502` diagnostics.
  * Responses include `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `X-Request-ID`.

---

## Reporting a Vulnerability

Please **do not** open public GitHub issues for suspected security vulnerabilities, policy bypasses, or credential exposures.

* **Contact:** Corey Allen Stickney / Lucid Tech via GitHub Security Advisories (`https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/security/advisories/new`).
* **Include:** Affected endpoint or policy pack, reproduction steps or sanitized payload, expected vs. actual behavior, and impact assessment.
* **Response Target:** Initial acknowledgment within **48 hours** and remediation plan within **5 business days**.