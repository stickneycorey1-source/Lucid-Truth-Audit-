from datetime import datetime, timezone
from pathlib import Path
import pytest

_RESULTS: list[dict] = []
_ERRORS: list[dict] = []


def pytest_html_report_title(report):
    report.title = "Lucid-Truth-Audit — AI Compliance & Guardrail Report"


def pytest_html_results_summary(prefix, summary, postfix):
    prefix.extend(
        [
            "<p><strong>Compliance Attestation Summary:</strong> Automated pre-deployment "
            "verification of input/output guardrails, strict Pydantic v2 schema enforcement, "
            "and adversarial prompt handling. Designed to generate auditable evidence aligned "
            "with EU AI Act risk-management and post-market monitoring expectations.</p>"
        ]
    )


def pytest_collectreport(report):
    """Capture collection-phase errors (0 tests, 1 Error)."""
    if report.failed:
        _ERRORS.append(
            {
                "nodeid": report.nodeid or "<collection>",
                "phase": "collection",
                "traceback": str(report.longrepr),
            }
        )


def pytest_runtest_logreport(report):
    """Capture per-test outcomes and setup/teardown errors."""
    if report.when == "call":
        _RESULTS.append(
            {
                "nodeid": report.nodeid,
                "outcome": report.outcome.upper(),
                "duration_ms": round(report.duration * 1000, 2),
                "traceback": str(report.longrepr) if report.failed else "",
            }
        )
    elif report.when == "setup" and report.failed:
        _ERRORS.append(
            {
                "nodeid": report.nodeid,
                "phase": "setup",
                "traceback": str(report.longrepr),
            }
        )
    elif report.when == "setup" and report.skipped:
        _RESULTS.append(
            {
                "nodeid": report.nodeid,
                "outcome": "SKIPPED",
                "duration_ms": round(report.duration * 1000, 2),
                "traceback": "",
            }
        )


def pytest_sessionfinish(session, exitstatus):
    """Write a Google-Docs-safe static Markdown compliance report."""
    report_dir = Path("reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    md_path = report_dir / "compliance_audit.md"

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    passed = sum(1 for r in _RESULTS if r["outcome"] == "PASSED")
    failed = sum(1 for r in _RESULTS if r["outcome"] == "FAILED")
    skipped = sum(1 for r in _RESULTS if r["outcome"] == "SKIPPED")
    errors = len(_ERRORS)

    lines = [
        "# Lucid-Truth-Audit — AI Compliance & Guardrail Report",
        f"**Generated:** {now_utc}  ",
        f"**Exit Code:** `{exitstatus}`",
        "",
        "## Summary",
        "| Passed | Failed | Errors | Skipped | Total Executed |",
        "| :---: | :---: | :---: | :---: | :---: |",
        f"| {passed} | {failed} | {errors} | {skipped} | {len(_RESULTS)} |",
        "",
        "## Test Matrix",
        "| Result | Test | Duration (ms) |",
        "| :--- | :--- | :---: |",
    ]

    if _RESULTS:
        for r in _RESULTS:
            lines.append(f"| **{r['outcome']}** | `{r['nodeid']}` | {r['duration_ms']} |")
    else:
        lines.append("| **NO TESTS EXECUTED** | See Error Tracebacks below | — |")

    failures_and_errors = _ERRORS + [
        {"nodeid": r["nodeid"], "phase": "call", "traceback": r["traceback"]}
        for r in _RESULTS
        if r["outcome"] == "FAILED"
    ]

    if failures_and_errors:
        lines.extend(["", "## Error & Failure Tracebacks"])
        for item in failures_and_errors:
            lines.extend(
                [
                    f"### `{item['nodeid']}` ({item['phase']})",
                    "```text",
                    item["traceback"],
                    "```",
                ]
            )

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
