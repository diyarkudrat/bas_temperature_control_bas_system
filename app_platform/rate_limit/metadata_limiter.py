from __future__ import annotations

import time


class MetadataLimiter:
    """Simple per-user/global limiter for metadata fetches."""

    def __init__(self, per_user_rpm: float = 100.0, global_rps: float = 1000.0):
        """Initialize the MetadataLimiter."""

        self._per_user_rpm = float(per_user_rpm) # Requests per minute per user
        self._global_rps = float(global_rps) # Requests per second globally
        self._user_window: dict[str, list[float]] = {} # Window for per-user requests
        self._global_window: list[float] = [] # Window for global requests

    def allow(self, user_id: str) -> bool:
        """Check if a request is allowed."""
        
        now = time.monotonic()

        # Per-user window: 60s
        wnd = self._user_window.setdefault(str(user_id), [])
        cutoff_user = now - 60.0

        self._user_window[user_id] = [t for t in wnd if t >= cutoff_user]

        if len(self._user_window[user_id]) >= int(self._per_user_rpm):
            return False

        # Global window: 1s
        cutoff_glob = now - 1.0
        self._global_window = [t for t in self._global_window if t >= cutoff_glob]

        if len(self._global_window) >= int(self._global_rps):
            return False

        # admit
        self._user_window[user_id].append(now)
        self._global_window.append(now)
        
        return True



_default_metadata_limiter = MetadataLimiter()


def rate_limit_metadata_fetch(user_id: str, weight: int = 1) -> tuple[bool, float]:
    """Compatibility API for metadata limiter.

    Returns (allowed, backoff_seconds). Backoff is 0.0 when allowed.
    """
    try:
        if not isinstance(user_id, str) or not user_id:
            return False, 0.05

        allowed = _default_metadata_limiter.allow(user_id)
        
        return (True, 0.0) if allowed else (False, 0.1)
    except Exception:
        # Fail-closed with minimal backoff
        return False, 0.1

