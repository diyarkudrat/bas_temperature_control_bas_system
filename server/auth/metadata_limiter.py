"""Metadata fetch rate limiter with per-user, global, and adaptive controls."""

from __future__ import annotations

import os
import time
import threading
from collections import deque
from typing import Tuple, Optional
import hashlib


class _TokenBucket:
    def __init__(self, capacity: float, refill_per_sec: float) -> None:
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def allow(self, weight: float = 1.0) -> Tuple[bool, float]:
        now = time.monotonic()
        with self.lock:
            elapsed = now - self.last_refill
            if elapsed > 0:
                self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
                self.last_refill = now
            if self.tokens >= weight:
                self.tokens -= weight
                return True, max(0.0, self.tokens)
            shortfall = weight - self.tokens
            backoff = shortfall / max(1e-6, self.refill_per_sec)
            return False, backoff


class _MetadataLimiter:
    def __init__(self) -> None:
        per_user_rpm = float(os.getenv("BAS_META_FETCH_PER_USER_RPM", "100"))
        global_rps = float(os.getenv("BAS_META_FETCH_GLOBAL_RPS", "1000"))
        burst_factor = float(os.getenv("BAS_META_FETCH_BURST_FACTOR", "2.0"))
        self.per_user_refill = per_user_rpm / 60.0
        self.per_user_capacity = max(1.0, self.per_user_refill * burst_factor)
        self.global_refill = global_rps
        self.global_capacity = max(1.0, global_rps * burst_factor)
        self._users: dict[str, _TokenBucket] = {}
        self._users_lock = threading.Lock()
        self._global_bucket = _TokenBucket(self.global_capacity, self.global_refill)
        # Adaptive window (success vs limited) to modulate per-user rate
        self._window_seconds = 10.0
        self._events = deque(maxlen=256)  # (ts, allowed: bool)
        self._adaptive_min_refill = self.per_user_refill * 0.25
        self._adaptive_max_refill = self.per_user_refill * 2.0
        self._adaptive_refill = self.per_user_refill

    def _get_user_bucket(self, user_id: str) -> _TokenBucket:
        with self._users_lock:
            bucket = self._users.get(user_id)
            if bucket is None:
                bucket = _TokenBucket(self.per_user_capacity, self._adaptive_refill)
                self._users[user_id] = bucket
            else:
                bucket.refill_per_sec = self._adaptive_refill
            return bucket

    def _record(self, allowed: bool) -> None:
        now = time.monotonic()
        self._events.append((now, allowed))
        cutoff = now - self._window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        total = len(self._events)
        if total >= 10:
            allowed_cnt = sum(1 for _, ok in self._events if ok)
            limited_ratio = 1.0 - (allowed_cnt / max(1, total))
            target = self.per_user_refill
            if limited_ratio > 0.2:
                target = max(self._adaptive_min_refill, self._adaptive_refill * 0.8)
            elif limited_ratio < 0.05:
                target = min(self._adaptive_max_refill, self._adaptive_refill * 1.1)
            self._adaptive_refill = target

    def check(self, user_id: str, weight: float = 1.0) -> Tuple[bool, float]:
        g_ok, g_backoff = self._global_bucket.allow(weight)
        if not g_ok:
            self._record(False)
            return False, min(2.0, max(0.01, g_backoff))
        user_bucket = self._get_user_bucket(user_id)
        u_ok, u_val = user_bucket.allow(weight)
        self._record(u_ok)
        if not u_ok:
            return False, min(2.0, max(0.01, u_val))
        return True, 0.0


_metadata_limiter = _MetadataLimiter()


def rate_limit_metadata_fetch(user_id: str, weight: int = 1) -> Tuple[bool, float]:
    """Apply per-user, global, and adaptive rate limiting for metadata fetches.

    Returns (allowed, backoff_seconds). If not allowed, caller should back off
    for suggested time with exponential strategy.
    """
    if not isinstance(user_id, str) or not user_id:
        return False, 0.05
    allowed, backoff = _metadata_limiter.check(user_id, float(weight))
    if not allowed:
        return False, max(0.05, min(1.0, backoff))
    return True, 0.0


# ---------------- Redis sliding-window per-user endpoint limiter ----------------
class RateLimiter:
    """Redis-backed sliding window limiter with bounded keys and Lua script.

    check_limit(user_id, endpoint, window_s, max_req, now) -> (allowed, remaining)

    - Uses a ZSET per (endpoint,user) with timestamps as scores
    - Keys are auto-expired at window_s to bound memory
    - On Redis/Lua error, denies by default (fail-closed)
    """

    def __init__(self, redis_client, key_prefix: str = "auth:rl", *, use_lua: bool = True, shards: int = 1) -> None:
        self._r = redis_client
        self._prefix = key_prefix
        self._use_lua = bool(use_lua)
        self._script_sha: Optional[str] = None
        self._shards = int(max(1, shards))

    def _key(self, endpoint: str, user_id: str) -> str:
        def _norm(s: str) -> str:
            return ''.join(ch if ch.isalnum() or ch in {':', '-', '_', '.'} else '_' for ch in s)[:200]
        base = f"{self._prefix}:{_norm(endpoint)}:{_norm(user_id)}"
        if self._shards <= 1:
            return base
        # Deterministic shard to spread keys across cluster slots
        h = hashlib.sha256(base.encode('utf-8')).digest()
        shard = int.from_bytes(h[:2], 'big') % self._shards
        return f"{self._prefix}:s{shard}:{_norm(endpoint)}:{_norm(user_id)}"

    def _load_script(self) -> None:
        if not self._use_lua or self._script_sha is not None:
            return
        script = (
            "local key=KEYS[1]; "
            "local now=tonumber(ARGV[1]); local window=tonumber(ARGV[2]); "
            "local max_req=tonumber(ARGV[3]); local member=ARGV[4]; "
            "redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window); "
            "redis.call('ZADD', key, now, member); "
            "local cnt=redis.call('ZCARD', key); "
            "redis.call('EXPIRE', key, math.ceil(window)); "
            "if cnt > max_req then return 0 else return 1 end"
        )
        try:
            self._script_sha = self._r.script_load(script)  # type: ignore[attr-defined]
        except Exception:
            # Fallback to direct eval on each call
            self._script_sha = None
            self._script_text = script  # type: ignore[attr-defined]

    def check_limit(self, user_id: str, endpoint: str, window_s: int, max_req: int, now: float) -> Tuple[bool, int]:
        key = self._key(endpoint, user_id)
        member = f"{int(now*1e6)}-{int((now%1)*1e6)}"
        try:
            if self._use_lua:
                self._load_script()
                try:
                    if getattr(self, '_script_sha', None):
                        # EVALSHA path
                        allowed = self._r.evalsha(self._script_sha, 1, key, float(now), int(window_s), int(max_req), member)  # type: ignore[attr-defined]
                    else:
                        allowed = self._r.eval(self._script_text, 1, key, float(now), int(window_s), int(max_req), member)  # type: ignore[attr-defined]
                except Exception:
                    return False, 0
                return (bool(int(allowed) == 1), 0)
            # Fallback path using basic commands
            # Prune old
            self._r.zremrangebyscore(key, '-inf', float(now) - int(window_s))
            # Add current
            try:
                self._r.zadd(key, {member: float(now)})
            except TypeError:
                self._r.zadd(key, {member: float(now)})
            # Count
            cnt = self._r.zcard(key)
            try:
                self._r.expire(key, int(window_s))
            except Exception:
                pass
            return (cnt <= int(max_req), int(cnt))
        except Exception:
            # Fail-closed on errors
            return False, 0