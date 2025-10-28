from __future__ import annotations

import time
from typing import Protocol, Optional, Iterable


class RevocationStore(Protocol):
    def add_revocation(self, token_id: str, reason: str = "") -> None: ...
    def is_revoked(self, token_id: str) -> bool: ...
    def get_revocation_reason(self, token_id: str) -> str | None: ...


class RedisRevocationStore:
    def __init__(self, redis_client, key: str = "auth:revocations", *, ttl_s: float | None = None, time_func=time.time, pubsub_channel: Optional[str] = "auth:revocations:invalidate", max_write_warn_rate: float = 100.0):
        self._r = redis_client
        self._key = key
        self._reasons_key = f"{key}:reasons"
        self._ttl_s = ttl_s
        self._now = time_func
        self._writes_window = []  # list[float]
        self._max_write_warn_rate = max_write_warn_rate
        self._pubsub_channel = pubsub_channel

    def _prune_if_needed(self, now_s: float) -> None:
        if self._ttl_s is None:
            return
        cutoff = now_s - float(self._ttl_s)
        try:
            expired = []
            try:
                expired = self._r.zrangebyscore(self._key, min="-inf", max=cutoff) or []
            except Exception:
                pass
            self._r.zremrangebyscore(self._key, "-inf", cutoff)
            if expired:
                try:
                    self._r.hdel(self._reasons_key, *[m.decode("utf-8") if isinstance(m, (bytes, bytearray)) else m for m in expired])
                except Exception:
                    for m in expired:
                        mid = m.decode("utf-8") if isinstance(m, (bytes, bytearray)) else m
                        try:
                            self._r.hdel(self._reasons_key, mid)
                        except Exception:
                            pass
        except Exception:
            pass

    def _record_write(self, now_s: float) -> None:
        self._writes_window.append(now_s)
        cutoff = now_s - 1.0
        if len(self._writes_window) > 0 and self._writes_window[0] < cutoff:
            self._writes_window = [t for t in self._writes_window if t >= cutoff]
        # warn suppressed here to keep adapter minimal

    def add_revocation(self, token_id: str, reason: str = "") -> None:
        now_s = float(self._now())
        self._prune_if_needed(now_s)
        try:
            try:
                self._r.zadd(self._key, {token_id: now_s}, nx=True)
            except TypeError:
                if self._r.zscore(self._key, token_id) is None:
                    self._r.zadd(self._key, {token_id: now_s})
            if reason:
                try:
                    self._r.hset(self._reasons_key, token_id, reason)
                except Exception:
                    pass
            if self._pubsub_channel:
                try:
                    self._r.publish(self._pubsub_channel, token_id)
                except Exception:
                    pass
        finally:
            self._record_write(now_s)

    def add_revocations_batch(self, token_ids: Iterable[str], reason: str = "") -> int:
        count = 0
        for tid in token_ids:
            try:
                self.add_revocation(str(tid), reason)
                count += 1
            except Exception:
                continue
        return count

    def is_revoked(self, token_id: str) -> bool:
        now_s = float(self._now())
        self._prune_if_needed(now_s)
        try:
            score = self._r.zscore(self._key, token_id)
            if score is None:
                return False
            if self._ttl_s is None:
                return True
            try:
                return (now_s - float(score)) <= float(self._ttl_s)
            except Exception:
                return True
        except Exception:
            return False

    def get_revocation_reason(self, token_id: str) -> str | None:
        try:
            val = self._r.hget(self._reasons_key, token_id)
            if val is None:
                return None
            if isinstance(val, (bytes, bytearray)):
                return val.decode("utf-8")
            return str(val)
        except Exception:
            return None

    def write_rate_last_sec(self) -> int:
        now_s = float(self._now())
        cutoff = now_s - 1.0
        self._writes_window = [t for t in self._writes_window if t >= cutoff]
        return len(self._writes_window)


class InMemoryRevocationStore:
    def __init__(self, *, ttl_s: float | None = None, time_func=time.time):
        self._ttl_s = ttl_s
        self._now = time_func
        self._data: dict[str, float] = {}
        self._reasons: dict[str, str] = {}

    def add_revocation(self, token_id: str, reason: str = "") -> None:
        now_s = float(self._now())
        self._data[token_id] = now_s
        if reason:
            self._reasons[token_id] = reason
        self._prune(now_s)

    def is_revoked(self, token_id: str) -> bool:
        now_s = float(self._now())
        ts = self._data.get(token_id)
        self._prune(now_s)
        if ts is None:
            return False
        if self._ttl_s is None:
            return True
        return (now_s - ts) <= float(self._ttl_s)

    def get_revocation_reason(self, token_id: str) -> str | None:
        return self._reasons.get(token_id)

    def _prune(self, now_s: float) -> None:
        if self._ttl_s is None:
            return
        cutoff = now_s - float(self._ttl_s)
        expired = [tid for tid, ts in self._data.items() if ts < cutoff]
        for tid in expired:
            self._data.pop(tid, None)
            self._reasons.pop(tid, None)


class RevocationService:
    def __init__(self, redis_client=None, key: str = "auth:revocations", *, ttl_s: float | None = None, time_func=time.time, max_write_warn_rate: float = 100.0, pubsub_channel: Optional[str] = "auth:revocations:invalidate"):
        if redis_client is None:
            self._store: RevocationStore = InMemoryRevocationStore(ttl_s=ttl_s, time_func=time_func)
        else:
            self._store = RedisRevocationStore(redis_client, key, ttl_s=ttl_s, time_func=time_func, pubsub_channel=pubsub_channel, max_write_warn_rate=max_write_warn_rate)

    def add_revocation(self, token_id: str, reason: str = "") -> None:
        self._store.add_revocation(token_id, reason)

    def is_revoked(self, token_id: str) -> bool:
        return self._store.is_revoked(token_id)

    def get_revocation_reason(self, token_id: str) -> str | None:
        return self._store.get_revocation_reason(token_id)

    def add_revocations_batch(self, token_ids: Iterable[str], reason: str = "") -> int:
        store = self._store
        if hasattr(store, "add_revocations_batch"):
            try:
                return int(getattr(store, "add_revocations_batch")(token_ids, reason))  # type: ignore[misc]
            except Exception:
                pass
        c = 0
        for tid in token_ids:
            try:
                store.add_revocation(str(tid), reason)
                c += 1
            except Exception:
                continue
        return c


