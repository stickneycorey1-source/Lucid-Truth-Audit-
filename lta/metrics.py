"""Lightweight zero-dependency Prometheus metrics collector for LTA Enterprise (v2.4.1)."""

from __future__ import annotations

import math
import threading
from collections import Counter, deque
from typing import Deque, Dict, List, Tuple


def _escape_prom_label(value: str) -> str:
    """Escape label values per the Prometheus text exposition format."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "")
    )


def _safe_latency_ms(latency_ms: float) -> float:
    val = float(latency_ms)
    if not math.isfinite(val) or val < 0.0:
        return 0.0
    return val


def _quantiles_from_samples(samples: List[float]) -> Dict[str, float]:
    if not samples:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0}
    ordered = sorted(samples)

    def _q(p: float) -> float:
        idx = min(len(ordered) - 1, max(0, int(round(p * (len(ordered) - 1)))))
        return round(ordered[idx], 3)

    return {"p50": _q(0.50), "p95": _q(0.95), "p99": _q(0.99)}


class MetricsRegistry:
    """Tracks aggregate request counts, block counts by vector, and latency quantiles (no tenant PII)."""

    def __init__(self, max_latency_samples: int = 5000) -> None:
        if max_latency_samples < 1:
            raise ValueError("max_latency_samples must be >= 1")
        self._lock = threading.Lock()
        self._requests: Counter[Tuple[str, int]] = Counter()
        self._blocks: Counter[Tuple[str, str]] = Counter()
        self._latencies_ms: Deque[float] = deque(maxlen=int(max_latency_samples))

    def observe(
        self,
        *,
        policy_pack: str,
        http_status: int,
        latency_ms: float,
        vector: str | None = None,
    ) -> None:
        pack = str(policy_pack)
        status_code = int(http_status)
        safe_latency = _safe_latency_ms(latency_ms)
        with self._lock:
            self._requests[(pack, status_code)] += 1
            if vector:
                self._blocks[(pack, str(vector))] += 1
            self._latencies_ms.append(safe_latency)

    def quantiles_ms(self) -> Dict[str, float]:
        with self._lock:
            samples = list(self._latencies_ms)
        return _quantiles_from_samples(samples)

    def render_prometheus(self) -> str:
        """Render metrics in standard Prometheus text exposition format."""
        with self._lock:
            req_items = sorted(self._requests.items())
            block_items = sorted(self._blocks.items())
            samples = list(self._latencies_ms)

        lines = [
            "# HELP lta_requests_total Total HTTP requests processed by Lucid-Truth-Audit",
            "# TYPE lta_requests_total counter",
        ]
        for (policy, status), count in req_items:
            safe_policy = _escape_prom_label(policy)
            lines.append(
                f'lta_requests_total{{policy="{safe_policy}",status="{status}"}} {count}'
            )

        lines.extend(
            [
                "# HELP lta_blocks_total Total threats or compliance violations blocked",
                "# TYPE lta_blocks_total counter",
            ]
        )
        for (policy, vector), count in block_items:
            safe_policy = _escape_prom_label(policy)
            safe_vector = _escape_prom_label(vector)
            lines.append(
                f'lta_blocks_total{{policy="{safe_policy}",vector="{safe_vector}"}} {count}'
            )

        q = _quantiles_from_samples(samples)
        lines.extend(
            [
                "# HELP lta_gateway_latency_ms Gateway processing latency quantiles in ms",
                "# TYPE lta_gateway_latency_ms gauge",
                f'lta_gateway_latency_ms{{quantile="0.50"}} {q["p50"]}',
                f'lta_gateway_latency_ms{{quantile="0.95"}} {q["p95"]}',
                f'lta_gateway_latency_ms{{quantile="0.99"}} {q["p99"]}',
            ]
        )
        return "\n".join(lines) + "\n"