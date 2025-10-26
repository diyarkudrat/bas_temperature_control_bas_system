"""Server configuration loader with emulator support."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

# Import split config components
from .rate_limit import RateLimitConfig
from .breaker import BreakerConfig
from .firestore_budgets import FirestoreBudgets
from .redis_budgets import RedisBudgets
from .sse_budgets import SSEBudgets
from .cache_ttls import CacheTTLs
from .auth0_configs import Auth0JWTBudgets, Auth0MgmtConfig


@dataclass
class ServerConfig:
    """Top-level server configuration used by services."""

    use_emulators: bool = False
    emulator_redis_url: Optional[str] = None
    firestore_emulator_host: Optional[str] = None
    gcp_project_id: Optional[str] = None
    # Authentication
    # Grouped under a dedicated dataclass for clarity and future growth
    # (e.g., JWKS caching budgets, token TTL clamps, etc.).
    # Added in Auth0 Phase 0.
    #
    # Defaults keep system functional in mock mode without external dependencies.
    # - provider: "mock"
    # - domain: dev placeholder
    # - audience: service identifier
    auth_provider: str = "mock"
    auth0_domain: Optional[str] = "dev-tenant"
    auth0_audience: Optional[str] = "bas-api"
    rate_limit: RateLimitConfig = RateLimitConfig()
    breaker: BreakerConfig = BreakerConfig()
    firestore: FirestoreBudgets = FirestoreBudgets()
    redis: RedisBudgets = RedisBudgets()
    sse: SSEBudgets = SSEBudgets()
    cache_ttl: CacheTTLs = CacheTTLs()
    # Auth0 Phase 2 budgets and management config
    auth0_jwt: Auth0JWTBudgets = Auth0JWTBudgets()
    auth0_mgmt: Auth0MgmtConfig = Auth0MgmtConfig()

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create configuration from environment variables."""
        use_emulators = os.getenv("USE_EMULATORS", "0") in {"1", "true", "True"}
        return cls(
            use_emulators=use_emulators,
            emulator_redis_url=os.getenv("EMULATOR_REDIS_URL"),
            firestore_emulator_host=os.getenv("FIRESTORE_EMULATOR_HOST"),
            gcp_project_id=os.getenv("GOOGLE_CLOUD_PROJECT"),
            auth_provider=os.getenv("AUTH_PROVIDER", "mock").strip().lower(),
            auth0_domain=os.getenv("AUTH0_DOMAIN", "dev-tenant"),
            auth0_audience=os.getenv("AUTH0_AUDIENCE", "bas-api"),
            rate_limit=RateLimitConfig.from_env(),
            breaker=BreakerConfig.from_env(),
            firestore=FirestoreBudgets.from_env(),
            redis=RedisBudgets.from_env(),
            sse=SSEBudgets.from_env(),
            cache_ttl=CacheTTLs.from_env(),
            auth0_jwt=Auth0JWTBudgets.from_env(),
            auth0_mgmt=Auth0MgmtConfig.from_env(),
        )


def get_server_config() -> ServerConfig:
    """Convenience accessor for callers that do not manage config lifecycle."""
    return ServerConfig.from_env()


