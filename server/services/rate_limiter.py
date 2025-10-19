from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class AlertRateLimitConfig:
    # Tokens per minute per key (e.g., per-tenant or global)
    tokens_per_minute: int = 60
    # Burst capacity (max tokens accumulated)
    burst_capacity: int = 30
    # Optional global caps per minute
    global_sms_per_minute: int = 300
    global_email_per_minute: int = 300


class _TokenBucket:
    def __init__(self, rate_per_minute: int, capacity: int):
        self.capacity = max(1, capacity)
        self.tokens = self.capacity
        self.rate_per_second = max(0.0, rate_per_minute / 60.0)
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def allow(self, cost: int = 1) -> bool:
        now = time.time()
        with self.lock:
            elapsed = now - self.last_refill
            refill = elapsed * self.rate_per_second
            if refill > 0:
                self.tokens = min(self.capacity, self.tokens + refill)
                self.last_refill = now
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False


class AlertRateLimiter:
    """
    Token-bucket limiter per key with shared global minute counters.
    Thread-safe; in multi-process deployments use a shared store (e.g., Redis).
    """
    def __init__(self, config: AlertRateLimitConfig):
        self.config = config
        self._buckets: Dict[str, _TokenBucket] = {}
        self._buckets_lock = threading.Lock()
        self._global_lock = threading.Lock()
        self._global_window_start = int(time.time() // 60)
        self._global_counts = {
            "sms": 0,
            "email": 0,
        }

    def _get_bucket(self, key: str) -> _TokenBucket:
        with self._buckets_lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _TokenBucket(
                    rate_per_minute=self.config.tokens_per_minute,
                    capacity=self.config.burst_capacity,
                )
                self._buckets[key] = bucket
            return bucket

    def _rotate_global_window_if_needed(self) -> None:
        current_window = int(time.time() // 60)
        if current_window != self._global_window_start:
            self._global_window_start = current_window
            self._global_counts = {"sms": 0, "email": 0}

    def _check_and_increment_global(self, channel: str) -> bool:
        with self._global_lock:
            self._rotate_global_window_if_needed()
            if channel == "sms":
                if self._global_counts["sms"] >= self.config.global_sms_per_minute:
                    return False
                self._global_counts["sms"] += 1
                return True
            if channel == "email":
                if self._global_counts["email"] >= self.config.global_email_per_minute:
                    return False
                self._global_counts["email"] += 1
                return True
            return False

    def allow(self, key: str, channel: str) -> Tuple[bool, str]:
        """
        Returns (allowed, reason). key can be tenant_id or 'global'.
        channel in {'sms','email'}.
        """
        # Per-key burst/rate check
        bucket = self._get_bucket(key)
        if not bucket.allow(1):
            return False, "burst_exceeded"
        # Global per-minute cap
        if not self._check_and_increment_global(channel):
            return False, "global_minute_cap_exceeded"
        return True, "ok"


