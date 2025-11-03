"""Reusable in-process rate limiter primitives."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict


class TokenBucket:
    """Thread-safe token bucket.

    Provides minimal primitives for in-memory rate limiting and allows callers to
    reuse a single implementation across different middleware layers.
    """

    def __init__(self, capacity: int, refill_rate_per_sec: float) -> None:
        self._lock = threading.Lock()
        self._capacity = max(1, capacity)
        self._refill_rate = max(0.0, refill_rate_per_sec)
        self._tokens = float(self._capacity)
        self._last_refill = time.monotonic()

    def configure(self, capacity: int, refill_rate_per_sec: float) -> None:
        """Update capacity/refill settings safely."""

        capacity = max(1, capacity)
        refill_rate_per_sec = max(0.0, refill_rate_per_sec)

        with self._lock:
            self._replenish_locked(time.monotonic())
            self._capacity = capacity
            self._refill_rate = refill_rate_per_sec
            self._tokens = min(self._tokens, float(self._capacity))

    def try_acquire(self, tokens: float = 1.0) -> tuple[bool, float]:
        """Attempt to consume tokens; return (allowed, remaining)."""

        if tokens <= 0:
            return True, self._tokens

        now = time.monotonic()

        with self._lock:
            self._replenish_locked(now)

            if self._tokens >= tokens:
                self._tokens -= tokens

                return True, self._tokens

            return False, self._tokens

    def allow(self) -> tuple[bool, float]:
        """Compatibility wrapper for single-token acquisitions."""

        return self.try_acquire(1.0)

    def _replenish_locked(self, now: float) -> None:
        """Replenish the tokens."""

        elapsed = now - self._last_refill
        
        if elapsed > 0:
            self._tokens = min(
                self._capacity,
                self._tokens + elapsed * self._refill_rate,
            )
            self._last_refill = now


class SlidingWindowLimiter:
    """Thread-safe sliding window limiter keyed by identifier."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._windows: Dict[str, Deque[float]] = {}

    def allow(self, key: str, quota: int, window_seconds: float) -> bool:
        """Return True when key stays within quota for the rolling window."""

        if quota <= 0:
            return False

        now = time.monotonic()
        window_seconds = max(1.0, float(window_seconds))

        with self._lock:
            window = self._windows.setdefault(key, deque())
            cutoff = now - window_seconds

            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= quota:
                return False

            window.append(now)
            return True


__all__ = ["TokenBucket", "SlidingWindowLimiter"]


