from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class BreakerConfig:
    """Circuit breaker defaults (see DDR notes)."""

    failure_threshold: int = 5            # trips after N failures
    window_seconds: int = 30              # rolling window for failure count
    half_open_after_seconds: int = 15     # time before trying half-open

    @classmethod
    def from_env(cls) -> "BreakerConfig":
        return cls(
            failure_threshold=int(os.getenv("BAS_BREAKER_FAILURES", "5")),
            window_seconds=int(os.getenv("BAS_BREAKER_WINDOW_S", "30")),
            half_open_after_seconds=int(os.getenv("BAS_BREAKER_HALF_OPEN_S", "15")),
        )



