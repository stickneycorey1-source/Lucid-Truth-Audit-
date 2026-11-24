import pytest


@pytest.fixture(autouse=True)
def isolate_runtime_state(monkeypatch, tmp_path):
    """Keep ledger and rate-limiter state isolated between tests."""
    monkeypatch.setenv(
        "LUCID_LEDGER_DB_PATH",
        str(tmp_path / "isolated_audit.db"),
    )

    try:
        from app.security import rate_limiter
        rate_limiter.reset()
    except Exception:
        pass

    yield

    try:
        from app.security import rate_limiter
        rate_limiter.reset()
    except Exception:
        pass