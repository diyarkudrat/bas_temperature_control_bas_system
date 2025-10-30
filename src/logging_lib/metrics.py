"""In-process metrics for the logging runtime."""

from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass
class RuntimeMetrics:
    """Runtime metrics for the logging library."""

    dropped_total: int = 0 # The total number of dropped records
    dropped_levels: dict[str, int] | None = None # The number of dropped records by level
    retries_total: int = 0 # The total number of retries
    flush_total: int = 0 # The total number of flushes
    last_flush_duration_ms: float = 0.0 # The duration of the last flush in milliseconds
    queue_depth: int = 0 # The depth of the queue

    def as_dict(self) -> dict[str, object]:
        """Return the metrics as a dictionary."""

        return {
            "dropped_total": self.dropped_total,
            "dropped_levels": dict(self.dropped_levels or {}),
            "retries_total": self.retries_total,
            "flush_total": self.flush_total,
            "last_flush_duration_ms": self.last_flush_duration_ms,
            "queue_depth": self.queue_depth,
        }


_LOCK = threading.RLock()
_METRICS = RuntimeMetrics(dropped_levels={})


def record_drop(level: str) -> None:
    """Record a drop of a record."""

    with _LOCK:
        _METRICS.dropped_total += 1
        levels = _METRICS.dropped_levels or {}
        levels[level] = levels.get(level, 0) + 1
        _METRICS.dropped_levels = levels


def record_retry() -> None:
    """Record a retry of a record."""

    with _LOCK:
        _METRICS.retries_total += 1


def record_flush(duration_ms: float, batch_size: int) -> None:
    """Record a flush of a batch of records."""

    with _LOCK:
        _METRICS.flush_total += batch_size
        _METRICS.last_flush_duration_ms = duration_ms


def set_queue_depth(depth: int) -> None:
    """Set the depth of the queue."""

    with _LOCK:
        _METRICS.queue_depth = depth


def reset_metrics() -> None:
    """Reset the metrics."""

    with _LOCK:
        _METRICS.dropped_total = 0
        _METRICS.dropped_levels = {}
        _METRICS.retries_total = 0
        _METRICS.flush_total = 0
        _METRICS.last_flush_duration_ms = 0.0
        _METRICS.queue_depth = 0


def get_metrics() -> RuntimeMetrics:
    """Get the metrics."""
    
    with _LOCK:
        snapshot = RuntimeMetrics(**_METRICS.as_dict())
        snapshot.dropped_levels = dict(_METRICS.dropped_levels or {})
        return snapshot


