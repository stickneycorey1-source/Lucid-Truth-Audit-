"""Unit tests covering hardening changes and edge branches in lta/metrics.py."""

from __future__ import annotations

import pytest

from lta.metrics import MetricsRegistry, _escape_prom_label, _safe_latency_ms


# ---------------------------------------------------------------------------
# 1. max_latency_samples validation & bounded window behavior
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_size", [0, -1, -100])
def test_init_rejects_non_positive_max_latency_samples(bad_size: int) -> None:
    with pytest.raises(ValueError, match="max_latency_samples must be >= 1"):
        MetricsRegistry(max_latency_samples=bad_size)


def test_max_latency_samples_bounds_retained_window() -> None:
    registry = MetricsRegistry(max_latency_samples=3)
    for val in (100.0, 200.0, 10.0, 20.0, 30.0):
        registry.observe(policy_pack="general", http_status=200, latency_ms=val)

    # Only the last 3 samples [10.0, 20.0, 30.0] remain
    assert registry.quantiles_ms() == {"p50": 20.0, "p95": 30.0, "p99": 30.0}


# ---------------------------------------------------------------------------
# 2. Empty quantiles & populated quantiles
# ---------------------------------------------------------------------------


def test_empty_registry_returns_zero_quantiles_and_valid_prometheus() -> None:
    registry = MetricsRegistry()
    assert registry.quantiles_ms() == {"p50": 0.0, "p95": 0.0, "p99": 0.0}

    rendered = registry.render_prometheus()
    assert "# TYPE lta_requests_total counter" in rendered
    assert "# TYPE lta_blocks_total counter" in rendered
    assert 'lta_gateway_latency_ms{quantile="0.50"} 0.0' in rendered
    assert 'lta_gateway_latency_ms{quantile="0.95"} 0.0' in rendered
    assert 'lta_gateway_latency_ms{quantile="0.99"} 0.0' in rendered
    assert rendered.endswith("\n")


# ---------------------------------------------------------------------------
# 3. Non-finite and negative latency clamping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_latency",
    [float("nan"), float("inf"), float("-inf"), -0.01, -500.0],
)
def test_safe_latency_clamps_non_finite_and_negative_values(bad_latency: float) -> None:
    assert _safe_latency_ms(bad_latency) == 0.0


def test_observe_clamps_non_finite_latencies_without_breaking_quantiles() -> None:
    registry = MetricsRegistry()
    registry.observe(policy_pack="general", http_status=200, latency_ms=float("nan"))
    registry.observe(policy_pack="general", http_status=200, latency_ms=float("inf"))
    registry.observe(policy_pack="general", http_status=200, latency_ms=-12.5)
    registry.observe(policy_pack="general", http_status=200, latency_ms=42.1234)

    q = registry.quantiles_ms()
    assert q["p50"] == 0.0
    assert q["p95"] == 42.123
    assert q["p99"] == 42.123


# ---------------------------------------------------------------------------
# 4. Prometheus label escaping (prevents metric-line injection)
# ---------------------------------------------------------------------------


def test_escape_prom_label_handles_quotes_backslashes_and_newlines() -> None:
    raw = 'pack"injected\nfake_metric 999\r\\tail'
    escaped = _escape_prom_label(raw)
    assert escaped == 'pack\\"injected\\nfake_metric 999\\\\tail'
    assert "\n" not in escaped
    assert "\r" not in escaped


def test_render_prometheus_escapes_policy_and_vector_labels() -> None:
    registry = MetricsRegistry()
    registry.observe(
        policy_pack='fin"pack\\1\n',
        http_status=400,
        latency_ms=5.5,
        vector='security."inject"\nfake_block 1',
    )

    rendered = registry.render_prometheus()
    assert 'lta_requests_total{policy="fin\\"pack\\\\1\\n",status="400"} 1' in rendered
    assert (
        'lta_blocks_total{policy="fin\\"pack\\\\1\\n",'
        'vector="security.\\"inject\\"\\nfake_block 1"} 1'
    ) in rendered
    # Ensure no injected unescaped metric line was created
    assert not any(line.startswith("fake_block ") for line in rendered.splitlines())