# Lucid-Truth-Audit (LTA)

[![Lucid Truth Audit CI](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions/workflows/ci.yml/badge.svg)](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-/actions)
![Test Suite](https://img.shields.io/badge/Pytest_Guardrail_Suite-17%2F17_Passing-10b981?style=flat&logo=pytest&logoColor=white)
![Live API](https://img.shields.io/badge/Live_Endpoint-Render_Active-38bdf8?style=flat&logo=fastapi&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11.18-3776ab?style=flat&logo=python&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2_Strict-e92063?style=flat&logo=pydantic&logoColor=white)
![Compliance](https://img.shields.io/badge/Compliance-EU_AI_Act_%7C_ISO%2FIEC_42001-6366f1?style=flat)
![License](https://img.shields.io/badge/License-MIT-slate?style=flat)

**Deterministic AI Compliance, Schema Guardrails, and Automated Red-Team Verification for Production LLM APIs.**

Lucid-Truth-Audit (LTA) wraps LLM endpoints in a defense-in-depth FastAPI and Pydantic v2 security gateway. Every request passes through fail-closed authentication, Unicode/encoding canonicalization, structural prompt isolation, and strict output boundary validation—generating auditable compliance artifacts aligned with **EU AI Act (Regulation (EU) 2024/1689)** and **ISO/IEC 42001** risk-management standards.

* **Live Interactive API & Swagger Docs:** [https://lucid-truth-audit.onrender.com/docs](https://lucid-truth-audit.onrender.com/docs)
* **GitHub Repository:** [https://github.com/stickneycorey1-source/Lucid-Truth-Audit-](https://github.com/stickneycorey1-source/Lucid-Truth-Audit-)
* **Enterprise Evaluation:** Request a 30-Day Shadow Pilot via repository Issues or direct contact with Lucid Truth.

---

## Defense-in-Depth Architecture

```text
Incoming Request ─► [1. Fail-Closed Auth: x-api-key Verification]
                        ├─► Missing / Invalid Key ───────────► 403 Forbidden (security.authentication_rejected)
                        ├─► Missing Server Secret ───────────► 500 Fail-Closed (security.configuration_error)
                        ▼
                    [2. Strict Input Schema: Pydantic v2 (extra="forbid")]
                        ├─► Unexpected Fields / Bad Shapes ──► 422 Unprocessable Entity
                        ▼
                    [3. Canonicalization & Heuristic Gateway]
                        ├─► Zero-Width / Cyrillic Homoglyph ─► 400 Bad Request (security.input_blocked)
                        ├─► Base64 / Hex Encoded Injection ──► 400 Bad Request (security.input_blocked)
                        ▼
                    [4. Structural Sandwich Isolation & LLM Execution]
                        ├─► XML <user_input> Boundary + Terminal Non-Disclosure Directive
                        ▼
                    [5. Output Boundary Validator: Pydantic v2]
                        ├─► Instruction / PII Leak Detected ─► 500 Blocked (security.output_rejected)
                        └─► Validated Payload ───────────────► 200 OK + Redacted Audit Ledger
```

---

## API Contract (`POST /api/v1/guard`)

### Request Headers & Body
* **Header:** `x-api-key: <your-configured-LTA_API_KEY>` (Required)
* **Content-Type:** `application/json`
* **Schema (`extra="forbid"`):**
```json
{
  "model_input": "Explain what a system prompt is in plain English."
}
```

### Deterministic HTTP Status Codes

| HTTP Status | Trigger Condition | Structured Audit Event |
| :--- | :--- | :--- |
| **`200 OK`** | Input clears canonicalization & output passes Pydantic v2 schema validation | Clean execution response |
| **`400 Bad Request`** | Direct, zero-width, Cyrillic homoglyph, Base64, or Hex injection detected | `security.input_blocked` |
| **`403 Forbidden`** | Missing or invalid `x-api-key` request header | `security.authentication_rejected` |
| **`422 Unprocessable`** | Unexpected JSON keys or malformed payload types rejected by Pydantic v2 | Schema validation failure |
| **`500 Internal Error`** | Unconfigured server secret (`fail-closed`) or output leak intercepted | `security.configuration_error` / `security.output_rejected` |

---

## Automated Red-Team & Guardrail Matrix (17/17 Passing)

Executed automatically via GitHub Actions (`Lucid Truth Audit CI`), producing downloadable `pytest-html` and JSON compliance attestation artifacts:

| Security Domain | Test Case (`test_audit.py`) | Attack / Validation Vector | Expected Outcome | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline Functionality** | `test_safe_prompt_is_allowed` | Standard domain query | `200 OK` | Passing |
| **False-Positive Control** | `test_benign_educational_prompt_is_allowed` | Educational query mentioning `"system prompt"` | `200 OK` | Passing |
| **Direct Injection** | `test_plain_and_obfuscated_injection_are_blocked[plain]` | Explicit instruction override + leak attempt | `400 Bad Request` | Passing |
| **Unicode Evasion** | `test_plain_and_obfuscated_injection_are_blocked[zero_width]` | Invisible `\u200b` zero-width splitting | `400 Bad Request` | Passing |
| **Homoglyph Evasion** | `test_plain_and_obfuscated_injection_are_blocked[cyrillic]` | Cyrillic lookalike character substitution | `400 Bad Request` | Passing |
| **Encoding Evasion (B64)** | `test_base64_encoded_injection_is_blocked` | Base64-obfuscated override payload | `400 Bad Request` | Passing |
| **Encoding Evasion (Hex)** | `test_hex_encoded_injection_is_blocked` | Hex-encoded override payload | `400 Bad Request` | Passing |
| **Auth Enforcement** | `test_missing_api_key_is_rejected` | Request omitting `x-api-key` header | `403 Forbidden` | Passing |
| **Auth Enforcement** | `test_invalid_api_key_is_rejected` | Request with unauthorized `x-api-key` | `403 Forbidden` | Passing |
| **Fail-Closed Posture** | `test_missing_server_secret_fails_closed` | Unconfigured server secret environment | Fail-Closed (`500`) | Passing |
| **Schema Strictness** | `test_unexpected_fields_are_rejected` | Extra JSON keys (`extra="forbid"`) | `422 Unprocessable` | Passing |
| **Payload Validation** | `test_invalid_request_shapes_are_rejected[0..3]` | 4 malformed types / missing required fields | `422 Unprocessable` | Passing |
| **Output Boundary** | `test_output_validator_rejects_instruction_leak` | Simulated system instruction exfiltration | Blocked (`500`) | Passing |
| **Log Privacy** | `test_block_event_does_not_log_raw_prompt` | Telemetry inspection on blocked requests | Raw prompt omitted | Passing |

---

## Quickstart & Local Verification

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the FastAPI Guardrail Service
```bash
export LTA_API_KEY="valid-test-key"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Execute the Red-Team Suite & Generate Compliance Artifacts
```bash
pytest test_audit.py -v --html=compliance_audit.html --self-contained-html
```

### 4. Smoke-Test the Live Production Endpoint
```bash
curl -X POST "https://lucid-truth-audit.onrender.com/api/v1/guard" \
  -H "x-api-key: valid-test-key" \
  -H "Content-Type: application/json" \
  -d '{"model_input": "Explain what a system prompt is in plain English."}'
```

---

## Regulatory & Governance Alignment

* **EU AI Act (Regulation (EU) 2024/1689):** Supports Article 9 (Risk Management System), Article 12 (Record-Keeping & Automated Logging), and Article 15 (Accuracy, Robustness, and Cybersecurity).
* **ISO/IEC 42001 (AI Management System):** Provides deterministic pre-deployment verification evidence and continuous post-market monitoring artifacts.

