"""Server configuration loader with emulator support."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


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


@dataclass
class FirestoreBudgets:
    """Firestore timeouts and retries."""

    read_timeout_ms: int = 50
    write_timeout_ms: int = 70
    retries: int = 2
    base_backoff_ms: int = 10
    max_backoff_ms: int = 100

    @classmethod
    def from_env(cls) -> "FirestoreBudgets":
        return cls(
            read_timeout_ms=int(os.getenv("BAS_FS_READ_TIMEOUT_MS", "50")),
            write_timeout_ms=int(os.getenv("BAS_FS_WRITE_TIMEOUT_MS", "70")),
            retries=int(os.getenv("BAS_FS_RETRIES", "2")),
            base_backoff_ms=int(os.getenv("BAS_FS_BACKOFF_BASE_MS", "10")),
            max_backoff_ms=int(os.getenv("BAS_FS_BACKOFF_MAX_MS", "100")),
        )


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


@dataclass
class CacheTTLs:
    """Centralized cache TTLs. Some are upper bounds; services may clamp by domain rules."""

    # Sessions: used as max TTL; services clamp to remaining expires_at
    session_max_seconds: int = 1800  # 30 minutes
    # Devices
    device_by_id_seconds: int = 60
    device_list_first_page_seconds: int = 60
    device_count_seconds: int = 30
    # Audit dashboard views
    audit_dashboard_seconds: int = 20

    @classmethod
    def from_env(cls) -> "CacheTTLs":
        return cls(
            session_max_seconds=int(os.getenv("BAS_TTL_SESSION_MAX_S", "1800")),
            device_by_id_seconds=int(os.getenv("BAS_TTL_DEVICE_BY_ID_S", "60")),
            device_list_first_page_seconds=int(os.getenv("BAS_TTL_DEVICE_LIST_S", "60")),
            device_count_seconds=int(os.getenv("BAS_TTL_DEVICE_COUNT_S", "30")),
            audit_dashboard_seconds=int(os.getenv("BAS_TTL_AUDIT_DASHBOARD_S", "20")),
        )


@dataclass
class ServerConfig:
    """Top-level server configuration used by services."""

    use_emulators: bool = False
    emulator_redis_url: Optional[str] = None
    firestore_emulator_host: Optional[str] = None
    gcp_project_id: Optional[str] = None
    rate_limit: RateLimitConfig = RateLimitConfig()
    breaker: BreakerConfig = BreakerConfig()
    firestore: FirestoreBudgets = FirestoreBudgets()
    redis: RedisBudgets = RedisBudgets()
    sse: SSEBudgets = SSEBudgets()
    cache_ttl: CacheTTLs = CacheTTLs()

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create configuration from environment variables."""
        use_emulators = os.getenv("USE_EMULATORS", "0") in {"1", "true", "True"}
        return cls(
            use_emulators=use_emulators,
            emulator_redis_url=os.getenv("EMULATOR_REDIS_URL"),
            firestore_emulator_host=os.getenv("FIRESTORE_EMULATOR_HOST"),
            gcp_project_id=os.getenv("GOOGLE_CLOUD_PROJECT"),
            rate_limit=RateLimitConfig.from_env(),
            breaker=BreakerConfig.from_env(),
            firestore=FirestoreBudgets.from_env(),
            redis=RedisBudgets.from_env(),
            sse=SSEBudgets.from_env(),
            cache_ttl=CacheTTLs.from_env(),
        )


def get_server_config() -> ServerConfig:
    """Convenience accessor for callers that do not manage config lifecycle."""
    return ServerConfig.from_env()


