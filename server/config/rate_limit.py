from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class RateLimitConfig:
    """Centralized request rate limit configuration with sane bounds."""

    enabled: bool = False
    shadow_mode: bool = False  # log-only
    requests_per_second: float = 50.0
    burst_capacity: int = 100

    # Bounds to prevent extreme/unintended values
    min_rps: float = 1.0
    max_rps: float = 10000.0
    min_burst: int = 1
    max_burst: int = 100000

    @classmethod
    def from_env(cls) -> "RateLimitConfig":
        enabled = os.getenv("BAS_REQ_RATE_LIMIT_ENABLED", "0").lower() in {"1", "true", "yes"}
        shadow_mode = os.getenv("BAS_REQ_RATE_LIMIT_SHADOW", "0").lower() in {"1", "true", "yes"}
        rps_raw = float(os.getenv("BAS_REQ_RATE_LIMIT_RPS", "50"))
        burst_raw = int(os.getenv("BAS_REQ_RATE_LIMIT_BURST", "100"))

        cfg = cls(enabled=enabled, shadow_mode=shadow_mode,
                  requests_per_second=rps_raw, burst_capacity=burst_raw)
        return cfg.clamped()

    def clamped(self) -> "RateLimitConfig":
        rps = max(self.min_rps, min(self.requests_per_second, self.max_rps))
        burst = max(self.min_burst, min(self.burst_capacity, self.max_burst))
        # Return a new instance to keep immutability semantics for callers
        return RateLimitConfig(
            enabled=self.enabled,
            shadow_mode=self.shadow_mode,
            requests_per_second=rps,
            burst_capacity=burst,
            min_rps=self.min_rps,
            max_rps=self.max_rps,
            min_burst=self.min_burst,
            max_burst=self.max_burst,
        )


