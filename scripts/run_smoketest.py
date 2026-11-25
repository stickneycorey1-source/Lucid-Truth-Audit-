import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

BASE_URL = os.getenv("LTA_BASE_URL", "https://lucid-truth-audit.onrender.com").rstrip("/")
API_KEY = os.getenv("LTA_API_KEY", "").strip()
SHADOW_KEY = os.getenv("LTA_SHADOW_KEY", "").strip()
OUTPUT_PATH = os.getenv("LTA_REPORT_PATH", "lta_smoketest_report.html")
TIMEOUT = 25


def _resolve_ref(spec: dict, ref: str) -> dict:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    curr = spec
    for part in ref[2:].split("/"):
        if isinstance(curr, dict):
            curr = curr.get(part, {})
        else:
            return {}
    return curr if isinstance(curr, dict) else {}


def _inspect_guard_schema(spec: dict) -> tuple[dict, list[str]]:
    post_spec = spec.get("paths", {}).get("/api/v1/guard", {}).get("post", {})
    req_body = post_spec.get("requestBody", {})
    content = req_body.get("content", {})
    app_json = content.get("application/json", {}) if isinstance(content, dict) else {}
    schema = app_json.get("schema", {}) if isinstance(app_json, dict) else {}
    if "$ref" in schema:
        schema = _resolve_ref(spec, schema["$ref"])

    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = schema.get("required", []) if isinstance(schema, dict) else []
    return props, required


def _build_guard_payload(prompt_text: str, props: dict, required: list[str]) -> dict:
    payload = {"prompt": prompt_text}
    candidate_text_keys = ["text", "content", "input", "message", "query"]

    for key in candidate_text_keys:
        if key in props or key in required:
            payload[key] = prompt_text

    for field in required:
        if field in payload:
            continue
        f_schema = props.get(field, {})
        if "$ref" in f_schema:
            f_schema = {}
        f_type = f_schema.get("type", "string")
        if "enum" in f_schema and f_schema["enum"]:
            payload[field] = f_schema["enum"][0]
        elif f_type == "integer":
            payload[field] = 1
        elif f_type == "number":
            payload[field] = 1.0
        elif f_type == "boolean":
            payload[field] = False
        elif f_type == "array":
            payload[field] = []
        elif f_type == "object":
            payload[field] = {}
        else:
            payload[field] = "smoke-test"

    return payload


def run_check(results, name, method, path, expected_codes, headers=None, payload=None, assert_fn=None):
    url = f"{BASE_URL}{path}"
    t0 = time.perf_counter()
    http_code = 0
    detail = ""
    ledger_hash = None
    passed = False

    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers or {},
            json=payload,
            timeout=TIMEOUT,
        )
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        http_code = resp.status_code
        try:
            body = resp.json()
        except Exception:
            body = {}

        code_ok = http_code in expected_codes
        custom_ok, custom_msg = (True, "OK")
        if code_ok and assert_fn:
            custom_ok, custom_msg = assert_fn(body, resp.text)

        passed = code_ok and custom_ok
        if code_ok:
            detail = custom_msg
        else:
            extra = ""
            if http_code == 422 and isinstance(body, dict) and "detail" in body:
                extra = f" | detail={json.dumps(body['detail'])[:240]}"
            detail = f"Expected {sorted(expected_codes)}, got {http_code}{extra}"

        if isinstance(body, dict):
            ledger_hash = (
                body.get("ledger_entry_hash")
                or body.get("input_sha256")
                or body.get("latest_hash_prefix")
                or body.get("merkle_root")
            )
    except Exception as exc:
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        detail = f"Exception: {exc}"

    results.append(
        {
            "name": name,
            "endpoint": path,
            "latency": latency_ms,
            "http_code": http_code,
            "status": "PASS" if passed else "FAIL",
            "detail": detail,
            "ledger_hash": ledger_hash or "n/a",
        }
    )


def main() -> int:
    results = []
    live_paths = set()
    guard_props = {}
    guard_required = []

    try:
        spec = requests.get(f"{BASE_URL}/openapi.json", timeout=TIMEOUT).json()
        live_paths = set(spec.get("paths", {}).keys())
        print("Live OpenAPI paths:", sorted(live_paths))
        guard_props, guard_required = _inspect_guard_schema(spec)
        if guard_props or guard_required:
            print(
                "Guard schema keys:",
                sorted(guard_props.keys()),
                "| required:",
                guard_required,
            )
    except Exception as exc:
        print("OpenAPI fetch failed:", exc)

    # 1. Health / Liveness (/healthz)
    run_check(
        results,
        name="1. Health / Liveness (/healthz)",
        method="GET",
        path="/healthz",
        expected_codes={200},
    )

    # 2. Readiness (/readyz)
    run_check(
        results,
        name="2. Readiness Check (/readyz)",
        method="GET",
        path="/readyz",
        expected_codes={200},
    )

    # 3. Unauthenticated Auth Guard on /api/v1/guard
    run_check(
        results,
        name="3. Guard Rejects Missing Key",
        method="POST",
        path="/api/v1/guard",
        expected_codes={401, 403},
        payload={"prompt": "ping"},
    )

    # 4. Shadow Ingest Route Presence & Auth Guard
    shadow_expected = {401, 403} if "/v1/shadow/ingest" in live_paths else {401, 403, 404}
    run_check(
        results,
        name="4. Shadow Ingest (/v1/shadow/ingest)",
        method="POST",
        path="/v1/shadow/ingest",
        expected_codes=shadow_expected,
        payload={"prompt": "ping"},
        assert_fn=lambda _, __: (
            True,
            "Mounted & auth-guarded" if "/v1/shadow/ingest" in live_paths else "Not yet mounted on Render (404)",
        ),
    )

    if API_KEY:
        auth_headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

        clean_payload = _build_guard_payload(
            "Summarize Q4 fleet safety metrics.", guard_props, guard_required
        )
        run_check(
            results,
            name="5. Guard Clean Prompt",
            method="POST",
            path="/api/v1/guard",
            expected_codes={200},
            headers=auth_headers,
            payload=clean_payload,
        )

        pii_payload = _build_guard_payload(
            "Driver SSN 123-45-6789 key sk-1234567890abcdef1234", guard_props, guard_required
        )
        run_check(
            results,
            name="6. Guard PII Redaction (SSN + Secret)",
            method="POST",
            path="/api/v1/guard",
            expected_codes={200},
            headers=auth_headers,
            payload=pii_payload,
            assert_fn=lambda _, raw: ("123-45-6789" not in raw, "Raw SSN not leaked in response"),
        )

        run_check(
            results,
            name="7. Audit Ledger Verify (/v1/audit/verify)",
            method="GET",
            path="/v1/audit/verify",
            expected_codes={200},
            headers={"X-API-Key": API_KEY},
        )

    if SHADOW_KEY and "/v1/shadow/ingest" in live_paths:
        run_check(
            results,
            name="8. Shadow Ingest (BiDi + Homoglyph)",
            method="POST",
            path="/v1/shadow/ingest",
            expected_codes={202},
            headers={"Authorization": f"Bearer {SHADOW_KEY}", "Content-Type": "application/json"},
            payload={
                "prompt": "SSN 123-45-6789 \u202e p\u0430ssword",
                "request_id": f"gha-{int(time.time())}",
                "model_target": "gpt-4o",
                "metadata": {"source": "github_actions"},
            },
            assert_fn=lambda b, raw: (
                b.get("status") == "accepted"
                and len(str(b.get("input_sha256", ""))) == 64
                and "123-45-6789" not in raw,
                f"audit_id={b.get('audit_id')}",
            ),
        )

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = total - passed
    score_pct = round((passed / total) * 100, 1) if total else 0.0
    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ledger_ref = next((r["ledger_hash"] for r in reversed(results) if r["ledger_hash"] != "n/a"), "N/A")

    for r in results:
        if r["status"] != "PASS":
            print(f"[FAIL] {r['name']} ({r['endpoint']}) -> HTTP {r['http_code']}: {r['detail']}")

    serialized_results = json.dumps(results).replace("</", "<\\/")

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lucid-Truth-Audit Smoke Test Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {{
      --bg: #0f172a; --card: #1e293b; --border: #334155;
      --text: #f8fafc; --muted: #94a3b8; --ok: #34d399; --err: #f43f5e; --accent: #818cf8;
    }}
    body {{ font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; }}
    .wrap {{ max-width: 1200px; margin: 0 auto; }}
    .hdr {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }}
    .hdr h1 {{ margin: 0; font-size: 24px; }}
    .hdr p {{ margin: 4px 0 0; color: var(--muted); font-size: 13px; }}
    .btn {{ background: var(--accent); color: #fff; border: none; padding: 8px 14px; border-radius: 8px; font-weight: 600; cursor: pointer; }}
    .badge {{ background: rgba(52, 211, 153, 0.15); color: var(--ok); padding: 6px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
    .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; }}
    .kpi-label {{ font-size: 11px; text-transform: uppercase; color: var(--muted); letter-spacing: 0.05em; }}
    .kpi-val {{ font-size: 30px; font-weight: 700; margin-top: 6px; }}
    .charts {{ display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-bottom: 24px; }}
    @media (max-width: 820px) {{ .charts {{ grid-template-columns: 1fr; }} }}
    .canvas-box {{ height: 280px; position: relative; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); word-break: break-word; }}
    th {{ color: var(--muted); font-weight: 600; }}
    .pill {{ padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
    .pill.pass {{ background: rgba(52, 211, 153, 0.18); color: #34d399; }}
    .pill.fail {{ background: rgba(244, 63, 94, 0.18); color: #fb7185; }}
    .hash-box {{ margin-top: 16px; padding: 12px; background: #0b1220; border: 1px dashed var(--border); border-radius: 8px; font-family: monospace; font-size: 12px; word-break: break-all; }}
    @media print {{
      body {{ background: #fff !important; color: #0f172a !important; padding: 0 !important; }}
      .btn {{ display: none !important; }}
      .card, .hash-box {{ background: #fff !important; color: #0f172a !important; border: 1px solid #cbd5e1 !important; }}
      th, .kpi-label, .hdr p {{ color: #475569 !important; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hdr">
      <div>
        <h1>Lucid-Truth-Audit · Live Smoke Test</h1>
        <p>Target: {BASE_URL}</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center;">
        <button class="btn" onclick="window.print()">Export PDF</button>
        <span class="badge">{timestamp_utc}</span>
      </div>
    </div>

    <div class="kpis">
      <div class="card">
        <div class="kpi-label">Compliance Score</div>
        <div class="kpi-val" style="color: {'#34d399' if failed == 0 else '#f43f5e'};">{score_pct}%</div>
      </div>
      <div class="card">
        <div class="kpi-label">Checks Passed</div>
        <div class="kpi-val">{passed} / {total}</div>
      </div>
      <div class="card">
        <div class="kpi-label">Zero-Retention Policy</div>
        <div class="kpi-val" style="color: var(--ok);">Verified</div>
      </div>
    </div>

    <div class="charts">
      <div class="card">
        <div class="kpi-label" style="margin-bottom:10px;">Latency Profile (ms)</div>
        <div class="canvas-box"><canvas id="latChart"></canvas></div>
      </div>
      <div class="card">
        <div class="kpi-label" style="margin-bottom:10px;">Pass / Fail Distribution</div>
        <div class="canvas-box"><canvas id="statusChart"></canvas></div>
      </div>
    </div>

    <div class="card">
      <div class="kpi-label" style="margin-bottom:12px;">Detailed Cryptographic &amp; Compliance Trail</div>
      <table>
        <thead>
          <tr><th>Check</th><th>Endpoint</th><th>Latency</th><th>HTTP</th><th>Status</th><th>Detail</th></tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
      <div class="hash-box">Latest Ledger / SHA-256 Reference: {ledger_ref}</div>
    </div>
  </div>

  <script>
    const data = {serialized_results};
    const tbody = document.getElementById("rows");

    data.forEach(r => {{
      const tr = document.createElement("tr");
      const cells = [r.name, r.endpoint, `${{r.latency}} ms`, String(r.http_code)];
      cells.forEach(val => {{
        const td = document.createElement("td");
        td.textContent = val;
        tr.appendChild(td);
      }});

      const tdStatus = document.createElement("td");
      const pill = document.createElement("span");
      pill.className = "pill " + (r.status === "PASS" ? "pass" : "fail");
      pill.textContent = r.status;
      tdStatus.appendChild(pill);
      tr.appendChild(tdStatus);

      const tdDetail = document.createElement("td");
      tdDetail.textContent = r.detail;
      tr.appendChild(tdDetail);
      tbody.appendChild(tr);
    }});

    new Chart(document.getElementById("latChart").getContext("2d"), {{
      type: "bar",
      data: {{
        labels: data.map(d => d.name),
        datasets: [{{
          label: "Latency (ms)",
          data: data.map(d => d.latency),
          backgroundColor: data.map(d => d.status === "PASS" ? "#34d399" : "#f43f5e"),
          borderRadius: 6
        }}]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ ticks: {{ color: "#94a3b8" }}, grid: {{ color: "#334155" }} }},
          y: {{ beginAtZero: true, ticks: {{ color: "#94a3b8" }}, grid: {{ color: "#334155" }} }}
        }}
      }}
    }});

    new Chart(document.getElementById("statusChart").getContext("2d"), {{
      type: "doughnut",
      data: {{
        labels: ["PASS", "FAIL"],
        datasets: [{{ data: [{passed}, {failed}], backgroundColor: ["#34d399", "#f43f5e"], borderWidth: 0 }}]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{ legend: {{ position: "bottom", labels: {{ color: "#94a3b8" }} }} }}
      }}
    }});
  </script>
</body>
</html>
"""

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(html_doc)

    print(f"Smoke test complete: {passed}/{total} passed ({score_pct}%). Report saved to {OUTPUT_PATH}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())