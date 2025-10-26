"""
Authentication metrics utilities.

Provides a low-overhead, thread-safe counter aggregator used by the
request middleware and routes to track JWT/session auth attempts and
simple latency statistics. Designed to be process-wide and safe to share.
"""

from __future__ import annotations

import threading


class AuthMetrics:
    """Low-overhead auth metrics aggregator.

    Thread-safe counters; latency sums in milliseconds for simple averages.
    Intentionally minimal to avoid hot-path overhead.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.jwt_attempts = 0
        self.jwt_failures = 0
        self.session_attempts = 0
        self.session_failures = 0
        self.jwt_latency_ms_sum = 0.0
        self.jwt_success = 0
        self.session_latency_ms_sum = 0.0
        self.session_success = 0

    def inc_jwt_attempt(self) -> None:
        with self._lock:
            self.jwt_attempts += 1

    def inc_jwt_failure(self) -> None:
        with self._lock:
            self.jwt_failures += 1

    def observe_jwt_success(self, latency_ms: float) -> None:
        with self._lock:
            self.jwt_success += 1
            self.jwt_latency_ms_sum += float(latency_ms)

    def inc_session_attempt(self) -> None:
        with self._lock:
            self.session_attempts += 1

    def inc_session_failure(self) -> None:
        with self._lock:
            self.session_failures += 1

    def observe_session_success(self, latency_ms: float) -> None:
        with self._lock:
            self.session_success += 1
            self.session_latency_ms_sum += float(latency_ms)

    def snapshot(self) -> dict:
        """Return a consistent snapshot of metrics counts and sums."""
        with self._lock:
            return {
                "jwt_attempts": self.jwt_attempts,
                "jwt_failures": self.jwt_failures,
                "jwt_success": self.jwt_success,
                "jwt_latency_ms_sum": self.jwt_latency_ms_sum,
                "session_attempts": self.session_attempts,
                "session_failures": self.session_failures,
                "session_success": self.session_success,
                "session_latency_ms_sum": self.session_latency_ms_sum,
            }


