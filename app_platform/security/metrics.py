"""Lightweight counters for security instrumentation."""

from __future__ import annotations

import threading
from collections import Counter
from types import MappingProxyType
from typing import Mapping

__all__ = ["SecurityMetrics", "security_metrics"]


class SecurityMetrics:
    """Thread-safe counter collection for security events."""

    def __init__(self) -> None:
        """Initialize the SecurityMetrics."""

        self._lock = threading.RLock()
        self._counters: Counter[str] = Counter()

    def incr(self, name: str, value: int = 1) -> None:
        """Increment a counter."""

        if value == 0:
            return

        with self._lock:
            self._counters[name] += value

    def snapshot(self) -> Mapping[str, int]:
        """Get a snapshot of the counters."""

        with self._lock:
            snapshot = dict[str, int](self._counters)

        return MappingProxyType[str, int](snapshot)

    def reset(self) -> None:
        """Reset the counters."""
        
        with self._lock:
            self._counters.clear()


security_metrics = SecurityMetrics()