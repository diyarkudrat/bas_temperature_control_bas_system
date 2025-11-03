"""Factory for building the auth provider."""

from __future__ import annotations

from typing import Any, Mapping
from .auth0 import Auth0Provider


def _require_str(cfg: Mapping[str, Any], key: str) -> str:
    """Require a string value in the configuration."""

    val = cfg.get(key)

    if not val or not isinstance(val, str) or not val.strip():
        raise ValueError(f"config[{key}] must be a non-empty string")

    return val.strip()


def build_auth0_provider(config: Mapping[str, Any]) -> Auth0Provider:
    """Build the Auth0 provider."""

    issuer = _require_str(config, "issuer") 
    audience = _require_str(config, "audience")

    jwks_url = config.get("jwks_url")
    if jwks_url is not None and (not isinstance(jwks_url, str) or not jwks_url.startswith("https://")):
        raise ValueError("jwks_url must be https URL string")

    jwks_cache_ttl_s = int(config.get("jwks_cache_ttl_s", 3600))
    jwks_timeout_s = int(config.get("jwks_timeout_s", 5))
    clock_skew_s = int(config.get("clock_skew_s", 0))
    
    return Auth0Provider(
        issuer=issuer,
        audience=audience,
        jwks_url=jwks_url,
        jwks_cache_ttl_s=jwks_cache_ttl_s,
        jwks_timeout_s=jwks_timeout_s,
        clock_skew_s=clock_skew_s,
    )


