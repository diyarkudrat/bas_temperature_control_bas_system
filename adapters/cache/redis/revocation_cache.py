from __future__ import annotations

import time


class LocalRevocationCache:
    """Lightweight in-process revocation cache with TTL to reduce Redis lookups.

    Tracks both positive (revoked) and negative (not revoked) results with
    separate TTLs to provide bounded staleness and stampede protection.
    """

    def __init__(self, ttl_s: float = 5.0, neg_ttl_s: float = 1.0, time_func=time.time):
        """Initialize the revocation cache."""

        self._ttl_s = float(ttl_s) # TTL
        self._neg_ttl_s = float(neg_ttl_s) # Negative TTL
        self._now = time_func # Time function
        self._revoked_ts: dict[str, float] = {} # Revoked timestamps
        self._not_revoked_ts: dict[str, float] = {} # Not revoked timestamps

    def set_revoked(self, token_id: str) -> None:
        """Set the revoked status for a token."""
        
        self._revoked_ts[str(token_id)] = float(self._now())

        # On positive result, clear any negative entry
        self._not_revoked_ts.pop(str(token_id), None)

    def set_not_revoked(self, token_id: str) -> None:
        """Set the not revoked status for a token."""

        self._not_revoked_ts[str(token_id)] = float(self._now())

    def is_recently_revoked(self, token_id: str) -> bool:
        """Check if a token is recently revoked."""

        ts = self._revoked_ts.get(str(token_id))
        if ts is None:
            return False

        return (float(self._now()) - ts) <= self._ttl_s

    def is_recently_not_revoked(self, token_id: str) -> bool:
        """Check if a token is recently not revoked."""

        ts = self._not_revoked_ts.get(str(token_id))
        if ts is None:
            return False

        return (float(self._now()) - ts) <= self._neg_ttl_s

    def prune(self) -> None:
        """Prune expired tokens."""

        cutoff_pos = float(self._now()) - self._ttl_s
        cutoff_neg = float(self._now()) - self._neg_ttl_s
        expired_pos = [tid for tid, ts in self._revoked_ts.items() if ts < cutoff_pos]

        for tid in expired_pos:
            self._revoked_ts.pop(tid, None)

        expired_neg = [tid for tid, ts in self._not_revoked_ts.items() if ts < cutoff_neg]

        for tid in expired_neg:
            self._not_revoked_ts.pop(tid, None)