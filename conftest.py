from datetime import datetime, timezone
from pytest_metadata.plugin import metadata_key


def pytest_html_report_title(report):
    """Set the browser tab and main H1 title of the HTML audit report."""
    report.title = "Lucid-Truth-Audit — AI Compliance & Guardrail Report"


def pytest_configure(config):
    """Populate the Environment metadata table using pytest-metadata's metadata_key."""
    if config.pluginmanager.getplugin("metadata"):
        config.stash[metadata_key]["Framework"] = (
            "Lucid-Truth-Audit (FastAPI + Pydantic v2)"
        )
        config.stash[metadata_key]["Regulatory Alignment"] = (
            "EU AI Act (Regulation (EU) 2024/1689) | ISO/IEC 42001"
        )
        config.stash[metadata_key]["Verification Scope"] = (
            "Deterministic Schema Guardrails & Red-Team Suite"
        )
        config.stash[metadata_key]["Audit Timestamp (UTC)"] = datetime.now(
            timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
        config.stash[metadata_key]["Owner"] = (
            "Corey Allen Stickney (Lucid Truth)"
        )


def pytest_html_results_summary(prefix, summary, postfix):
    """Inject a branded compliance executive summary above the test results."""
    prefix.extend(
        [
            "<div style='padding:12px 16px;margin:12px 0;border-left:4px solid #3186ff;"
            "background:#f4f7fb;border-radius:6px;font-family:sans-serif;'>"
            "<strong>Compliance Attestation Summary:</strong> "
            "Automated pre-deployment verification of input/output guardrails, "
            "strict Pydantic v2 schema enforcement, and adversarial prompt handling. "
            "Designed to generate auditable evidence aligned with EU AI Act "
            "risk-management and post-market monitoring expectations."
            "</div>"
        ]
    )
