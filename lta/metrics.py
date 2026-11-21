"""Lightweight zero-dependency Prometheus metrics collector for LTA Enterprise (v2.2)."""

from __future__ import annotations

import threading
from collections import Counter, deque
from typing import Deque, Dict, Tuple


class MetricsRegistry:
    """Tracks aggregate request counts, block counts by vector, and latency quantiles (no tenant PII)."""

    def __init__(self, max_latency_samples: int = 5000) -> None:
        self._lock = threading.Lock()
        self._requests: Counter[Tuple[str, int]] = Counter()
        self._blocks: Counter[Tuple[str, str]] = Counter()
        self._latencies_ms: Deque[float] = deque(maxlen=max_latency_samples)

    def observe(
        self,
        *,
        policy_pack: str,
        http_status: int,
        latency_ms: float,
        vector: str | None = None,
    ) -> None:
        with self._lock:
            self._requests[(policy_pack, http_status)] += 1
            if vector:
                self._blocks[(policy_pack, vector)] += 1
            self._latencies_ms.append(latency_ms)

    def quantiles_ms(self) -> Dict[str, float]:
        with self._lock:
            samples = sorted(self._latencies_ms)
        if not samples:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0}

        def _q(p: float) -> float:
            idx = min(len(samples) - 1, max(0, int(round(p * (len(samples) - 1)))))
            return round(samples[idx], 3)

        return {"p50": _q(0.50), "p95": _q(0.95), "p99": _q(0.99)}

    def render_prometheus(self) -> str:
        """Render metrics in standard Prometheus text exposition format."""
        lines = [
            "# HELP lta_requests_total Total HTTP requests processed by Lucid-Truth-Audit",
            "# TYPE lta_requests_total counter",
        ]
        with self._lock:
            for (policy, status), count in sorted(self._requests.items()):
                lines.append(
                    f'lta_requests_total{{policy="{policy}",status="{status}"}} {count}'
                )
            lines.extend(
                [
                    "# HELP lta_blocks_total Total threats or compliance violations blocked",
                    "# TYPE lta_blocks_total counter",
                ]
            )
            for (policy, vector), count in sorted(self._blocks.items()):
                lines.append(
                    f'lta_blocks_total{{policy="{policy}",vector="{vector}"}} {count}'
                )
        q = self.quantiles_ms()
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
