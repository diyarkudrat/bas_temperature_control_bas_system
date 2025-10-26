from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Auth0JWTBudgets:
    """Auth0 JWT & roles caching budgets and tolerances."""

    jwks_cache_ttl_s: int = 3600
    jwks_timeout_s: int = 5
    clock_skew_s: int = 0
    roles_cache_ttl_s: int = 60
    # Max tolerated seconds a roles version may be considered stale before forced refresh
    roles_version_stale_s: int = 120

    @classmethod
    def from_env(cls) -> "Auth0JWTBudgets":
        return cls(
            jwks_cache_ttl_s=int(os.getenv("AUTH0_JWKS_CACHE_TTL_S", "3600")),
            jwks_timeout_s=int(os.getenv("AUTH0_JWKS_TIMEOUT_S", "5")),
            clock_skew_s=int(os.getenv("AUTH0_CLOCK_SKEW_S", "0")),
            roles_cache_ttl_s=int(os.getenv("AUTH0_ROLES_CACHE_TTL_S", "60")),
            roles_version_stale_s=int(os.getenv("AUTH0_ROLES_VERSION_STALE_S", "120")),
        )


@dataclass
class Auth0MgmtConfig:
    """Auth0 Management API credentials and budgets (Phase 2)."""

    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    audience: Optional[str] = None
    base_url: Optional[str] = None
    timeout_s: int = 5
    retries: int = 3
    backoff_base_ms: int = 50
    backoff_max_ms: int = 1000
    # Lightweight client-side rate limit to avoid bursts
    rps: float = 5.0
    burst: int = 10

    @classmethod
    def from_env(cls) -> "Auth0MgmtConfig":
        return cls(
            client_id=os.getenv("AUTH0_MGMT_CLIENT_ID"),
            client_secret=os.getenv("AUTH0_MGMT_CLIENT_SECRET"),
            audience=os.getenv("AUTH0_MGMT_AUDIENCE"),
            base_url=os.getenv("AUTH0_MGMT_BASE_URL"),
            timeout_s=int(os.getenv("AUTH0_MGMT_TIMEOUT_S", "5")),
            retries=int(os.getenv("AUTH0_MGMT_RETRIES", "3")),
            backoff_base_ms=int(os.getenv("AUTH0_MGMT_BACKOFF_BASE_MS", "50")),
            backoff_max_ms=int(os.getenv("AUTH0_MGMT_BACKOFF_MAX_MS", "1000")),
            rps=float(os.getenv("AUTH0_MGMT_RPS", "5")),
            burst=int(os.getenv("AUTH0_MGMT_BURST", "10")),
        )


