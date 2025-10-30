"""Lightweight counters for security instrumentation."""

from __future__ import annotations

import threading
from collections import Counter
from typing import Dict

__all__ = ["SecurityMetrics", "security_metrics"]


class SecurityMetrics:
    """Thread-safe counter collection for security events."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counters: Counter[str] = Counter()

    def incr(self, name: str, value: int = 1) -> None:
        if value == 0:
            return
        with self._lock:
            self._counters[name] += value

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counters)

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()


security_metrics = SecurityMetrics()


