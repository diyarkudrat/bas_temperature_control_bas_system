from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import threading


@dataclass
class RateLimitConfig:
    """Centralized request rate limit configuration with sane bounds."""

    enabled: bool = False
    shadow_mode: bool = False  # log-only
    requests_per_second: float = 50.0
    burst_capacity: int = 100
    # Dynamic per-user endpoint limits; set via admin API at runtime
    # Shape: {endpoint: {"window_s": int, "max_req": int}}
    per_user_limits: Dict[str, Dict[str, int]] = field(default_factory=dict)

    # Bounds to prevent extreme/unintended values
    min_rps: float = 1.0
    max_rps: float = 10000.0
    min_burst: int = 1
    max_burst: int = 100000

    @classmethod
    def from_env(cls) -> "RateLimitConfig":
        """Create a RateLimitConfig from environment variables."""

        enabled = os.getenv("BAS_REQ_RATE_LIMIT_ENABLED", "0").lower() in {"1", "true", "yes"}
        shadow_mode = os.getenv("BAS_REQ_RATE_LIMIT_SHADOW", "0").lower() in {"1", "true", "yes"}
        rps_raw = float(os.getenv("BAS_REQ_RATE_LIMIT_RPS", "50"))
        burst_raw = int(os.getenv("BAS_REQ_RATE_LIMIT_BURST", "100"))

        cfg = cls(
            enabled=enabled,
            shadow_mode=shadow_mode,
            requests_per_second=rps_raw,
            burst_capacity=burst_raw,
        )

        return cfg.clamped()

    def clamped(self) -> "RateLimitConfig":
        """Clamp the RateLimitConfig to the configured bounds."""

        rps = max(self.min_rps, min(self.requests_per_second, self.max_rps))
        burst = max(self.min_burst, min(self.burst_capacity, self.max_burst))

        # Return a new instance to keep immutability semantics for callers
        return RateLimitConfig(
            enabled=self.enabled,
            shadow_mode=self.shadow_mode,
            requests_per_second=rps,
            burst_capacity=burst,
            per_user_limits=dict(self.per_user_limits),
            min_rps=self.min_rps,
            max_rps=self.max_rps,
            min_burst=self.min_burst,
            max_burst=self.max_burst,
        )

    # ---------------- Runtime dynamic limits API ----------------
    def __post_init__(self) -> None:  # type: ignore[override]
        """Initialize the RateLimitConfig."""

        # Thread-safety for runtime updates
        self._lock = threading.Lock()

    def set_per_user_limit(self, endpoint: str, window_s: int, max_req: int) -> None:
        """Set a per-user limit for an endpoint."""

        if not isinstance(endpoint, str) or not endpoint.strip():
            raise ValueError("endpoint must be a non-empty string")
        if not isinstance(window_s, int) or window_s <= 0:
            raise ValueError("window_s must be a positive integer")
        if not isinstance(max_req, int) or max_req <= 0:
            raise ValueError("max_req must be a positive integer")

        with self._lock:
            self.per_user_limits[endpoint.strip()] = {
                "window_s": int(window_s),
                "max_req": int(max_req),
            }

    def update_per_user_limits(self, limits: Dict[str, Dict[str, Any]]) -> None:
        """Update the per-user limits for an endpoint."""

        if not isinstance(limits, dict):
            raise ValueError("limits must be a mapping of endpoint -> {window_s,max_req}")

        # Validate all first before mutating
        validated: Dict[str, Dict[str, int]] = {}

        for ep, cfg in limits.items():
            if not isinstance(ep, str) or not ep.strip():
                raise ValueError("endpoint keys must be non-empty strings")

            if not isinstance(cfg, dict):
                raise ValueError("limit entry must be a mapping with window_s and max_req")

            ws = cfg.get("window_s")
            mr = cfg.get("max_req")

            if not isinstance(ws, int) or ws <= 0:
                raise ValueError("window_s must be a positive integer")

            if not isinstance(mr, int) or mr <= 0:
                raise ValueError("max_req must be a positive integer")

            validated[ep.strip()] = {"window_s": int(ws), "max_req": int(mr)}
            
        with self._lock:
            self.per_user_limits.update(validated)

    def get_per_user_limits_snapshot(self) -> Dict[str, Dict[str, int]]:
        """Get a snapshot of the per-user limits."""

        with self._lock:
            return dict(self.per_user_limits)


class AtomicRateLimitConfig:
    """Thread-safe holder for hot-reloading RateLimitConfig.

    Provides atomic swap of the active configuration and read-only snapshots
    for callers. All updates are clamped to configured minima/maxima.
    """

    def __init__(self, initial: Optional[RateLimitConfig] = None) -> None:
        """Initialize the AtomicRateLimitConfig."""

        self._lock = threading.RLock()
        self._cfg: RateLimitConfig = (initial or RateLimitConfig()).clamped()
        self._version: int = 0

    def get_snapshot(self) -> RateLimitConfig:
        """Get a snapshot of the RateLimitConfig."""

        with self._lock:
            # Return a fresh instance to discourage external mutation
            return RateLimitConfig(
                enabled=self._cfg.enabled,
                shadow_mode=self._cfg.shadow_mode,
                requests_per_second=self._cfg.requests_per_second,
                burst_capacity=self._cfg.burst_capacity,
                per_user_limits=dict(self._cfg.per_user_limits),
                min_rps=self._cfg.min_rps,
                max_rps=self._cfg.max_rps,
                min_burst=self._cfg.min_burst,
                max_burst=self._cfg.max_burst,
            )

    def version(self) -> int:
        """Get the version of the RateLimitConfig."""

        with self._lock:
            return self._version

    def swap(self, new_cfg: RateLimitConfig) -> RateLimitConfig:
        """Swap the RateLimitConfig with a new one."""

        with self._lock:
            self._cfg = new_cfg.clamped()
            self._version += 1
            return self.get_snapshot()

    def update(
        self,
        *,
        enabled: Optional[bool] = None,
        shadow_mode: Optional[bool] = None,
        requests_per_second: Optional[float] = None,
        burst_capacity: Optional[int] = None,
        per_user_limits: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> RateLimitConfig:
        """Update the RateLimitConfig with a new one."""

        with self._lock:
            base = self.get_snapshot()

            if enabled is not None:
                base.enabled = bool(enabled)
            if shadow_mode is not None:
                base.shadow_mode = bool(shadow_mode)

            if requests_per_second is not None:
                try:
                    base.requests_per_second = float(requests_per_second)
                except Exception:
                    # keep previous on parse error
                    pass

            if burst_capacity is not None:
                try:
                    base.burst_capacity = int(burst_capacity)
                except Exception:
                    pass

            if per_user_limits is not None:
                try:
                    base.update_per_user_limits(per_user_limits)
                except Exception:
                    # ignore invalid batch updates to preserve current limits
                    pass

            # Clamp and swap atomically
            self._cfg = base.clamped()
            self._version += 1

            return self.get_snapshot()


@dataclass
class MetadataFetchRateLimit:
    """Rate limits for auth metadata fetches (per-user/global + burst factor)."""

    per_user_requests_per_minute: float = 100.0
    global_requests_per_second: float = 1000.0
    burst_factor: float = 2.0

    # Bounds
    min_per_user_rpm: float = 10.0
    max_per_user_rpm: float = 10000.0
    min_global_rps: float = 10.0
    max_global_rps: float = 50000.0
    min_burst_factor: float = 1.0
    max_burst_factor: float = 10.0

    @classmethod
    def from_env(cls) -> "MetadataFetchRateLimit":
        """Create a MetadataFetchRateLimit from environment variables."""

        per_user_rpm = float(os.getenv("BAS_META_FETCH_PER_USER_RPM", "100"))
        global_rps = float(os.getenv("BAS_META_FETCH_GLOBAL_RPS", "1000"))
        burst_factor = float(os.getenv("BAS_META_FETCH_BURST_FACTOR", "2.0"))
        cfg = cls(
            per_user_requests_per_minute=per_user_rpm,
            global_requests_per_second=global_rps,
            burst_factor=burst_factor,
        )
        
        return cfg.clamped()

    def clamped(self) -> "MetadataFetchRateLimit":
        """Clamp the MetadataFetchRateLimit to the configured bounds."""

        rpm = max(self.min_per_user_rpm, min(self.per_user_requests_per_minute, self.max_per_user_rpm))
        rps = max(self.min_global_rps, min(self.global_requests_per_second, self.max_global_rps))
        bf = max(self.min_burst_factor, min(self.burst_factor, self.max_burst_factor))

        return MetadataFetchRateLimit(
            per_user_requests_per_minute=rpm,
            global_requests_per_second=rps,
            burst_factor=bf,
            min_per_user_rpm=self.min_per_user_rpm,
            max_per_user_rpm=self.max_per_user_rpm,
            min_global_rps=self.min_global_rps,
            max_global_rps=self.max_global_rps,
            min_burst_factor=self.min_burst_factor,
            max_burst_factor=self.max_burst_factor,
        )



