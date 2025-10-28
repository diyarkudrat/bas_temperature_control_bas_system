from __future__ import annotations

import time


class LocalRevocationCache:
    """Lightweight in-process revocation cache with TTL to reduce Redis lookups."""

    def __init__(self, ttl_s: float = 5.0, time_func=time.time):
        self._ttl_s = float(ttl_s)
        self._now = time_func
        self._data: dict[str, float] = {}

    def set_revoked(self, token_id: str) -> None:
        self._data[str(token_id)] = float(self._now())

    def is_recently_revoked(self, token_id: str) -> bool:
        ts = self._data.get(str(token_id))
        if ts is None:
            return False
        return (float(self._now()) - ts) <= self._ttl_s

    def prune(self) -> None:
        cutoff = float(self._now()) - self._ttl_s
        expired = [tid for tid, ts in self._data.items() if ts < cutoff]
        for tid in expired:
            self._data.pop(tid, None)


