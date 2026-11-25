import json
import os
import time
import uuid
from urllib import error, request

BASE_URL = os.environ.get("LTA_BASE_URL", "https://lucid-truth-audit.onrender.com").rstrip("/")
API_KEY = os.environ["LTA_API_KEY"]
SHADOW_KEY = os.environ["LTA_SHADOW_KEY"]


def call_api(method: str, path: str, payload: dict | None = None, headers: dict | None = None):
    hdrs = {
        "Content-Type": "application/json",
        "X-Request-ID": f"gemini-ci-{uuid.uuid4().hex[:10]}",
    }
    if headers:
        hdrs.update(headers)
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = request.Request(f"{BASE_URL}{path}", data=data, headers=hdrs, method=method)
    t0 = time.perf_counter()
    try:
        with request.urlopen(req, timeout=45) as resp:
            ms = round((time.perf_counter() - t0) * 1000.0, 1)
            return resp.status, ms, resp.read().decode("utf-8", errors="replace")
    except error.HTTPError as exc:
        ms = round((time.perf_counter() - t0) * 1000.0, 1)
        return exc.code, ms, exc.read().decode("utf-8", errors="replace")


# 1. Pre-warm & verify readiness
r_code, r_ms, r_body = call_api("GET", "/readyz")
assert r_code == 200, f"/readyz failed ({r_code}): {r_body}"
print(f"[PASS] /readyz -> {r_code} in {r_ms} ms")

# 2. Live Gemini clean guard turn
c_code, c_ms, c_body = call_api(
    "POST",
    "/api/v1/guard",
    {"model_input": "Respond with the single word READY.", "metadata": {"check": "gemini_clean"}},
    {"X-API-Key": API_KEY},
)
assert c_code == 200, f"Clean guard failed ({c_code}): {c_body}"
c_json = json.loads(c_body)
assert c_json.get("usage", {}).get("total_tokens", 0) >= 0
print(f"[PASS] Guard clean prompt -> {c_code} in {c_ms} ms (action={c_json.get('action')})")

# 3. Live Gemini PII + secret redaction turn
p_code, p_ms, p_body = call_api(
    "POST",
    "/api/v1/guard",
    {
        "model_input": "Redact this test record: SSN 123-45-6789 and API key sk-live-demo-9999. Reply REDACTED_OK.",
        "metadata": {"check": "gemini_redaction"},
    },
    {"X-API-Key": API_KEY},
)
assert p_code == 200, f"Redaction guard failed ({p_code}): {p_body}"
assert "123-45-6789" not in p_body and "sk-live-demo-9999" not in p_body, "Sensitive token leaked in response"
p_json = json.loads(p_body)
print(
    f"[PASS] Guard redaction -> {p_code} in {p_ms} ms "
    f"(action={p_json.get('action')}, redactions={p_json.get('redactions')})"
)

# 4. Shadow ingest + ledger chain verification
s_code, s_ms, s_body = call_api(
    "POST",
    "/v1/shadow/ingest",
    {
        "prompt": "Shadow Gemini check \u202e p\u0430ssword",
        "request_id": "ci-shadow-check",
        "model_target": "gemini-2.5-flash-lite",
    },
    {"Authorization": f"Bearer {SHADOW_KEY}"},
)
assert s_code == 202, f"Shadow ingest failed ({s_code}): {s_body}"
s_json = json.loads(s_body)
assert s_json.get("zero_retention") is True and len(s_json.get("input_sha256", "")) == 64

v_code, v_ms, v_body = call_api("GET", "/v1/audit/verify", headers={"X-API-Key": API_KEY})
assert v_code == 200 and json.loads(v_body).get("chain_valid") is True, f"Ledger verify failed: {v_body}"
print(f"[PASS] Shadow ingest ({s_ms} ms) + Ledger verify ({v_ms} ms) -> sha256={s_json['input_sha256'][:16]}...")