"""Global rate limiting utilities for the API service."""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional, Tuple, Any

from flask import jsonify, request

from logging_lib import get_logger as get_structured_logger


logger = get_structured_logger("api.http.middleware.rate_limit")


class _TokenBucket:
    """Token bucket rate limiter."""
    
    def __init__(self, capacity: int, refill_rate_per_sec: float) -> None:
        self.capacity = max(1, capacity)
        self.refill_rate_per_sec = max(0.1, refill_rate_per_sec)
        self.tokens = float(self.capacity)
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def update(self, capacity: int, refill_rate_per_sec: float) -> None:
        with self.lock:
            capacity = max(1, capacity)
            refill_rate_per_sec = max(0.1, refill_rate_per_sec)
            now = time.monotonic()
            elapsed = now - self.last_refill
            if elapsed > 0:
                self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate_per_sec)
                self.last_refill = now
            self.capacity = capacity
            self.refill_rate_per_sec = refill_rate_per_sec
            self.tokens = min(self.tokens, float(self.capacity))

    def allow(self) -> Tuple[bool, float]:
        now = time.monotonic()
        with self.lock:
            elapsed = now - self.last_refill
            if elapsed > 0:
                self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate_per_sec)
                self.last_refill = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True, self.tokens
            return False, self.tokens


class GlobalRateLimiter:
    """Token bucket rate limiter keyed by client IP."""

    def __init__(self) -> None:
        self._buckets: Dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()

    def _get_bucket(self, key: str, capacity: int, refill_rate: float) -> _TokenBucket:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _TokenBucket(capacity, refill_rate)
                self._buckets[key] = bucket
            else:
                bucket.update(capacity, refill_rate)
            return bucket

    def check(self, *, key: str, capacity: int, refill_rate: float) -> Tuple[bool, float]:
        bucket = self._get_bucket(key, capacity, refill_rate)
        return bucket.allow()


def enforce_global_rate_limit() -> Optional[Tuple[Any, int]]:
    """Apply IP-based rate limiting using server configuration."""

    cfg = getattr(request, "rate_limit_snapshot", None)
    if cfg is None:
        server_cfg = getattr(request, "server_config", None)
        cfg = getattr(server_cfg, "rate_limit", None)

    if cfg is None or not getattr(cfg, "enabled", False):
        return None

    endpoint = request.endpoint or ""
    if endpoint.startswith("health") or endpoint.endswith("health"):
        return None

    remote_addr = request.remote_addr or "unknown"
    key = remote_addr

    from flask import current_app  # local import to avoid circular import

    limiter: GlobalRateLimiter
    limiter = current_app.config.setdefault("global_rate_limiter", GlobalRateLimiter())  # type: ignore[assignment]

    allowed, remaining = limiter.check(
        key=key,
        capacity=int(getattr(cfg, "burst_capacity", 100)),
        refill_rate=float(getattr(cfg, "requests_per_second", 50.0)),
    )

    if allowed or getattr(cfg, "shadow_mode", False):
        if not allowed:
            logger.info(
                "Global rate limit shadow hit",
                extra={"ip": remote_addr, "endpoint": endpoint, "remaining": remaining},
            )
        return None

    logger.warning(
        "Global rate limit enforced",
        extra={"ip": remote_addr, "endpoint": endpoint, "remaining": remaining},
    )

    response = jsonify({
        "error": "Too many requests",
        "code": "GLOBAL_RATE_LIMITED",
        "ip": remote_addr,
    })
    response.status_code = 429
    return response, 429


__all__ = ["enforce_global_rate_limit", "GlobalRateLimiter"]


