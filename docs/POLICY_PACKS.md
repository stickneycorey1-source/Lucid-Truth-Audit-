# Regulatory Policy Packs & Detection Vectors

Lucid-Truth-Audit (`v2.4.1`) evaluates requests and upstream responses against domain-specific YAML policy packs loaded from `LTA_POLICY_DIR` (default `policies`).

---

## Supported Policy Packs

* **Healthcare (`healthcare_hipaa`):**
  * Redacts Medical Record Numbers (`MRN`), Social Security Numbers (`SSN`), and sensitive patient identifiers before upstream dispatch and on outputs.
  * Enforces clinical data boundaries against unauthorized export or exfiltration prompts.
* **Finance (`finance_pci`):**
  * Applies Luhn-validated Primary Account Number (`PAN`) redaction while preserving non-card reference identifiers.
  * Evaluates transaction context such as `wire_amount_usd` metadata alongside content guardrails.
* **Logistics (`logistics_fmcsa`):**
  * Redacts multi-state Commercial Driver's Licenses (`CDL` / `DL`) while preserving Purchase Orders (`PO`) and manifest references.
  * Validates operational metadata including `driving_hours`, `duty_window_hours` (60/7 and 70/8 cycle limits), `gross_weight_lbs`, and `break_minutes`.
  * Blocks indirect prompt injections embedded in Bills of Lading (`BOL`) and unauthorized waypoint/rerouting attempts.
* **General Enterprise (`general_enterprise`):**
  * Baseline PII redaction, prompt-injection/evasion blocking, social-engineering pretext defense, and output secret/instruction boundary protection.

---

## Core Threat & Anomaly Vectors

* **Prompt Injection & Obfuscation:** Direct overrides, zero-width characters, BiDi control characters (`\u202e`), Cyrillic/Unicode homoglyphs, combining marks, leetspeak, Base64, and hex-encoded injection payloads.
* **Multi-Turn & Role Spoofing:** Unauthorized `system` messages after turn `0` or from non-admin tenants (`security.multi_turn_system_spoofing`), cross-turn split injections, and poisoned `assistant` history turns.
* **Social Engineering & Pretexting:** Impersonation of system administrators, security auditors, or compliance officers attempting to bypass controls or exfiltrate records.
* **Flood & Resilience Anomalies:** Repeating-character floods, repeating-word floods, high-entropy gibberish floods, and per-tenant sliding-window rate limit breaches (`429`).
* **Output Boundary Violations:** Prevents upstream responses from leaking internal system instructions, raw SSNs, or API secrets (`sk-...`, `ghp_...`, `AKIA...`, `AIza...`).
