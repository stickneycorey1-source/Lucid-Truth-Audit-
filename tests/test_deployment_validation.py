from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_uses_expected_entrypoint_and_healthcheck():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM python:3.11-slim" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "uvicorn" in dockerfile


def test_render_config_has_healthcheck_and_persistent_storage():
    config = yaml.safe_load(
        (ROOT / "render.yaml").read_text(encoding="utf-8")
    )
    service = config["services"][0]

    assert service["healthCheckPath"] == "/health"
    assert service["disk"]["mountPath"] == "/var/data"


def test_compose_config_names_required_services():
    config = yaml.safe_load(
        (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    )

    assert {"lta-gateway", "postgres", "redis"}.issubset(
        config["services"]
    )

    gateway = config["services"]["lta-gateway"]
    assert (
        gateway["depends_on"]["postgres"]["condition"]
        == "service_healthy"
    )
    assert (
        gateway["depends_on"]["redis"]["condition"]
        == "service_healthy"
    )


def test_ci_runs_complete_validation_suite():
    ci = (
        ROOT / ".github" / "workflows" / "ci.yml"
    ).read_text(encoding="utf-8")

    assert "--cov-fail-under=60" in ci
    assert "pip_audit" in ci
    assert "docker build" in ci