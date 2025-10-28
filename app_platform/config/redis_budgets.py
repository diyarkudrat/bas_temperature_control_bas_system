from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class RedisBudgets:
    """Redis connection pool and op timeouts."""

    op_timeout_ms: int = 10
    pool_max_connections: int = 64

    @classmethod
    def from_env(cls) -> "RedisBudgets":
        return cls(
            op_timeout_ms=int(os.getenv("BAS_REDIS_OP_TIMEOUT_MS", "10")),
            pool_max_connections=int(os.getenv("BAS_REDIS_POOL_MAX", "64")),
        )



