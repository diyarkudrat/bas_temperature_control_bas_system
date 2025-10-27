from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class SSEBudgets:
    """SSE service timings and retries."""

    keepalive_seconds: int = 20
    retry_base_ms: int = 250
    retry_max_ms: int = 5000

    @classmethod
    def from_env(cls) -> "SSEBudgets":
        return cls(
            keepalive_seconds=int(os.getenv("BAS_SSE_KEEPALIVE_S", "20")),
            retry_base_ms=int(os.getenv("BAS_SSE_RETRY_BASE_MS", "250")),
            retry_max_ms=int(os.getenv("BAS_SSE_RETRY_MAX_MS", "5000")),
        )


