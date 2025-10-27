"""Server configuration loader with emulator support."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional
import json
import re
import logging

# Import split config components
from .rate_limit import RateLimitConfig, MetadataFetchRateLimit
from .breaker import BreakerConfig
from .firestore_budgets import FirestoreBudgets
from .redis_budgets import RedisBudgets
from .sse_budgets import SSEBudgets
from .cache_ttls import CacheTTLs
from .auth0_configs import Auth0JWTBudgets, Auth0MgmtConfig

logger = logging.getLogger(__name__)


def _validate_path_rules(rules):
    """Validate path sensitivity rules: list of (pattern, level).

    Returns only valid entries; logs warnings for invalid patterns.
    """
    valid = []
    if not isinstance(rules, (list, tuple)):
        return valid
    for item in rules:
        try:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                pattern, level = str(item[0]), str(item[1])
            elif isinstance(item, dict) and 'pattern' in item and 'level' in item:
                pattern, level = str(item['pattern']), str(item['level'])
            else:
                logger.warning(f"Invalid path rule entry (ignored): {item}")
                continue
            # Compile to validate regex; re has no timeout, but compile is quick for sane patterns
            re.compile(pattern)
            # Normalize level to lowercase tokens like 'critical'|'standard'|... (free-form)
            valid.append((pattern, level.lower()))
        except re.error as exc:
            logger.warning(f"Invalid path rule regex '{item}': {exc}")
        except Exception as exc:
            logger.warning(f"Failed to parse path rule '{item}': {exc}")
    if valid:
        logger.info(f"Loaded {len(valid)} path sensitivity rules")
    else:
        logger.info("No path sensitivity rules configured; default fail-closed applies")
    return valid


def _load_path_rules_from_env():
    """Load path sensitivity rules from BAS_PATH_SENS_RULES (JSON)."""
    raw = os.getenv("BAS_PATH_SENS_RULES", "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return _validate_path_rules(data)
    except Exception as exc:
        logger.warning(f"Failed to parse BAS_PATH_SENS_RULES: {exc}")
        return []


def _get_int_env(name: str, default: int, *, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        val = int(os.getenv(name, str(default)))
        if min_value is not None and val < min_value:
            raise ValueError(f"{name} must be >= {min_value}")
        if max_value is not None and val > max_value:
            raise ValueError(f"{name} must be <= {max_value}")
        return val
    except Exception as exc:
        logger.warning(f"Invalid integer for {name}: {exc}; using default {default}")
        return int(default)


def _load_per_user_limits_from_env() -> dict:
    """Load USER_RATE_WINDOWS JSON mapping endpoint -> {window_s,max_req}."""
    raw = os.getenv("USER_RATE_WINDOWS", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("must be a JSON object")
        validated: dict[str, dict[str, int]] = {}
        for ep, cfg in data.items():
            if not isinstance(ep, str) or not ep.strip():
                logger.warning(f"Invalid endpoint key in USER_RATE_WINDOWS: {ep}")
                continue
            if not isinstance(cfg, dict):
                logger.warning(f"Invalid cfg for endpoint {ep} (not object)")
                continue
            ws = cfg.get("window_s")
            mr = cfg.get("max_req")
            if not isinstance(ws, int) or ws <= 0 or not isinstance(mr, int) or mr <= 0:
                logger.warning(f"Invalid window/max for endpoint {ep}")
                continue
            validated[ep.strip()] = {"window_s": int(ws), "max_req": int(mr)}
        return validated
    except Exception as exc:
        logger.warning(f"Failed to parse USER_RATE_WINDOWS: {exc}")
        return {}


def _load_breaker_thresholds_from_env() -> dict:
    """Load BREAKER_THRESHOLDS JSON with optional keys: failure_threshold, window_seconds, half_open_after_seconds."""
    raw = os.getenv("BREAKER_THRESHOLDS", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("must be a JSON object")
        result: dict[str, int] = {}
        for k in ("failure_threshold", "window_seconds", "half_open_after_seconds"):
            if k in data:
                v = int(data[k])
                if v <= 0:
                    raise ValueError(f"{k} must be positive")
                result[k] = v
        return result
    except Exception as exc:
        logger.warning(f"Failed to parse BREAKER_THRESHOLDS: {exc}")
        return {}


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
    # Path sensitivity rules used by middleware.path_classify()
    # List of (regex_pattern, level). Empty => default fail-closed to 'critical'.
    PATH_SENSITIVITY_RULES: list[tuple[str, str]] = None  # type: ignore
    # Metadata fetch rate limiting (global/per-user)
    metadata_rate_limit: MetadataFetchRateLimit = MetadataFetchRateLimit()
    # Phase 4 additions
    revocation_ttl_s: Optional[int] = None
    dynamic_limit_api_key: Optional[str] = None

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create configuration from environment variables."""
        use_emulators = os.getenv("USE_EMULATORS", "0") in {"1", "true", "True"}
        # Path rules from env (optional); default empty for fail-closed behavior
        path_rules = _load_path_rules_from_env()
        # Per-user limits seed from env
        per_user_limits_env = _load_per_user_limits_from_env()
        # Breaker thresholds optional overrides
        breaker_over = _load_breaker_thresholds_from_env()

        # Build sub-configs
        rate_limit_cfg = RateLimitConfig.from_env()
        if per_user_limits_env:
            try:
                rate_limit_cfg.update_per_user_limits(per_user_limits_env)
            except Exception as exc:
                logger.warning(f"Ignoring invalid USER_RATE_WINDOWS: {exc}")

        breaker_cfg = BreakerConfig.from_env()
        try:
            if breaker_over.get("failure_threshold"):
                breaker_cfg.failure_threshold = int(breaker_over["failure_threshold"])  # type: ignore[attr-defined]
            if breaker_over.get("window_seconds"):
                breaker_cfg.window_seconds = int(breaker_over["window_seconds"])  # type: ignore[attr-defined]
            if breaker_over.get("half_open_after_seconds"):
                breaker_cfg.half_open_after_seconds = int(breaker_over["half_open_after_seconds"])  # type: ignore[attr-defined]
        except Exception as exc:
            logger.warning(f"Ignoring invalid BREAKER_THRESHOLDS overrides: {exc}")

        return cls(
            use_emulators=use_emulators,
            emulator_redis_url=os.getenv("EMULATOR_REDIS_URL"),
            firestore_emulator_host=os.getenv("FIRESTORE_EMULATOR_HOST"),
            gcp_project_id=os.getenv("GOOGLE_CLOUD_PROJECT"),
            auth_provider=os.getenv("AUTH_PROVIDER", "mock").strip().lower(),
            auth0_domain=os.getenv("AUTH0_DOMAIN", "dev-tenant"),
            auth0_audience=os.getenv("AUTH0_AUDIENCE", "bas-api"),
            rate_limit=rate_limit_cfg,
            breaker=breaker_cfg,
            firestore=FirestoreBudgets.from_env(),
            redis=RedisBudgets.from_env(),
            sse=SSEBudgets.from_env(),
            cache_ttl=CacheTTLs.from_env(),
            auth0_jwt=Auth0JWTBudgets.from_env(),
            auth0_mgmt=Auth0MgmtConfig.from_env(),
            PATH_SENSITIVITY_RULES=path_rules,
            metadata_rate_limit=MetadataFetchRateLimit.from_env(),
            revocation_ttl_s=_get_int_env("REVOCATION_TTL_S", 3600, min_value=1),
            dynamic_limit_api_key=os.getenv("DYNAMIC_LIMIT_API_KEY"),
        )


def get_server_config() -> ServerConfig:
    """Convenience accessor for callers that do not manage config lifecycle."""
    return ServerConfig.from_env()


