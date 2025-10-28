from __future__ import annotations

import hashlib
from typing import Tuple, Optional


class RateLimiter:
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
                        allowed = self._r.evalsha(self._script_sha, 1, key, float(now), int(window_s), int(max_req), member)  # type: ignore[attr-defined]
                    else:
                        allowed = self._r.eval(self._script_text, 1, key, float(now), int(window_s), int(max_req), member)  # type: ignore[attr-defined]
                except Exception:
                    return False, 0
                return (bool(int(allowed) == 1), 0)
            self._r.zremrangebyscore(key, '-inf', float(now) - int(window_s))
            try:
                self._r.zadd(key, {member: float(now)})
            except TypeError:
                self._r.zadd(key, {member: float(now)})
            cnt = self._r.zcard(key)
            try:
                self._r.expire(key, int(window_s))
            except Exception:
                pass
            return (cnt <= int(max_req), int(cnt))
        except Exception:
            return False, 0


