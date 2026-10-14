"""Small in-process metrics for the health page (task 027). Prometheus export is optional later."""
from __future__ import annotations

import time
from collections import deque


class LatencyStats:
    """The last `size` durations (ms) within `window_seconds`."""

    def __init__(self, size: int = 1000, window_seconds: int = 900) -> None:
        self.samples: deque[tuple[float, float]] = deque(maxlen=size)
        self.window = window_seconds

    def observe(self, milliseconds: float) -> None:
        self.samples.append((time.monotonic(), milliseconds))

    def snapshot(self) -> dict:
        cutoff = time.monotonic() - self.window
        values = sorted(ms for at, ms in self.samples if at >= cutoff)
        if not values:
            return {"count": 0, "p50_ms": None, "p95_ms": None}
        pick = lambda q: round(values[min(len(values) - 1, int(q * len(values)))], 1)  # noqa: E731
        return {"count": len(values), "p50_ms": pick(0.5), "p95_ms": pick(0.95)}


scoring_latency = LatencyStats()
