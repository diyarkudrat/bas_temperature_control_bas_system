from __future__ import annotations

import time


class LocalRevocationCache:
    """Lightweight in-process revocation cache with TTL to reduce Redis lookups.

    Tracks both positive (revoked) and negative (not revoked) results with
    separate TTLs to provide bounded staleness and stampede protection.
    """

    def __init__(self, ttl_s: float = 5.0, neg_ttl_s: float = 1.0, time_func=time.time):
        self._ttl_s = float(ttl_s)
        self._neg_ttl_s = float(neg_ttl_s)
        self._now = time_func
        self._revoked_ts: dict[str, float] = {}
        self._not_revoked_ts: dict[str, float] = {}

    def set_revoked(self, token_id: str) -> None:
        self._revoked_ts[str(token_id)] = float(self._now())
        # On positive result, clear any negative entry
        self._not_revoked_ts.pop(str(token_id), None)

    def set_not_revoked(self, token_id: str) -> None:
        self._not_revoked_ts[str(token_id)] = float(self._now())

    def is_recently_revoked(self, token_id: str) -> bool:
        ts = self._revoked_ts.get(str(token_id))
        if ts is None:
            return False
        return (float(self._now()) - ts) <= self._ttl_s

    def is_recently_not_revoked(self, token_id: str) -> bool:
        ts = self._not_revoked_ts.get(str(token_id))
        if ts is None:
            return False
        return (float(self._now()) - ts) <= self._neg_ttl_s

    def prune(self) -> None:
        cutoff_pos = float(self._now()) - self._ttl_s
        cutoff_neg = float(self._now()) - self._neg_ttl_s
        expired_pos = [tid for tid, ts in self._revoked_ts.items() if ts < cutoff_pos]
        for tid in expired_pos:
            self._revoked_ts.pop(tid, None)
        expired_neg = [tid for tid, ts in self._not_revoked_ts.items() if ts < cutoff_neg]
        for tid in expired_neg:
            self._not_revoked_ts.pop(tid, None)


