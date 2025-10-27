from __future__ import annotations

import hashlib
from typing import Tuple

from .metadata_limiter import RateLimiter


class SlidingWindowLimiter:
    """Facade over RateLimiter adding deterministic jitter and sharding.

    Deterministic jitter reduces herd effects by slightly varying window per (user,endpoint).
    """

    def __init__(self, redis_client, key_prefix: str = "auth:rl", *, shards: int = 1, use_lua: bool = True, jitter_range: float = 0.1) -> None:
        self._rl = RateLimiter(redis_client, key_prefix=key_prefix, use_lua=use_lua, shards=shards)
        self._jitter_range = float(max(0.0, min(0.5, jitter_range)))

    def _jittered_window(self, user_id: str, endpoint: str, window_s: int) -> int:
        if self._jitter_range <= 0.0:
            return int(window_s)
        seed = f"{user_id}|{endpoint}".encode('utf-8')
        h = hashlib.sha256(seed).digest()
        # Map first 2 bytes to [-1, 1]
        val = (int.from_bytes(h[:2], 'big') / 65535.0) * 2.0 - 1.0
        jitter = 1.0 + (self._jitter_range * float(val))
        return max(1, int(round(float(window_s) * jitter)))

    def check(self, user_id: str, endpoint: str, window_s: int, max_req: int, now: float) -> Tuple[bool, int]:
        w = self._jittered_window(user_id, endpoint, window_s)
        return self._rl.check_limit(user_id, endpoint, w, max_req, now)


