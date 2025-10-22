"""Small, dependency-free circuit breaker primitives for SSE paths."""
from __future__ import annotations

import time
import threading
from collections import deque
from typing import List
        # imports reordered; functionality unchanged


class CircuitBreaker:
	"""Lightweight circuit breaker with time-window failure tracking.

	Attributes are tuned for fast, low-overhead decisioning on hot paths.
	Default policy matches Phase 3 plan: threshold 5 events / 30s, reset after 15s.
	"""

    def __init__(self, failure_threshold: int = 5, window_s: float = 30.0, reset_timeout_s: float = 15.0) -> None:
        self._failure_threshold = max(1, failure_threshold)
        self._window_s = window_s
        self._reset_timeout_s = reset_timeout_s
        self._failures = deque()  # type: ignore[var-annotated]
        self._open_until: float = 0.0
        self._lock = threading.RLock()

	def allow_call(self) -> bool:
        with self._lock:
            now = time.monotonic()
            if now < self._open_until:
                return False
            cutoff = now - self._window_s
            while self._failures and self._failures[0] < cutoff:
                self._failures.popleft()
            return True

	def on_success(self) -> None:
        with self._lock:
            self._open_until = 0.0
            self._failures.clear()

	def on_failure(self) -> None:
        with self._lock:
            now = time.monotonic()
            # Ensure non-decreasing timestamps to keep deque ordered
            if self._failures:
                last = self._failures[-1]
                if now < last:
                    now = last
            self._failures.append(now)
            cutoff = now - self._window_s
            while self._failures and self._failures[0] < cutoff:
                self._failures.popleft()
            if len(self._failures) >= self._failure_threshold:
                self._open_until = now + self._reset_timeout_s

	def state(self) -> dict:
		"""Return a lightweight state snapshot for observability/tests."""
		with self._lock:
			return {
				"open_until": self._open_until,
				"failures": len(self._failures),
				"threshold": self._failure_threshold,
				"window_s": self._window_s,
				"reset_timeout_s": self._reset_timeout_s,
			}