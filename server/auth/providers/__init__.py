"""
Authentication providers package.

Exports provider interface and implementations:
- AuthProvider
- MockAuth0Provider
- Auth0Provider

Also provides a small factory for constructing Auth0Provider with config validation.
"""

import logging
from typing import Any, Dict, List, Mapping, Optional

__all__ = [
    "AuthProvider",
    "MockAuth0Provider",
    "Auth0Provider",
    "build_auth0_provider",
]

logger = logging.getLogger(__name__)


# Import interface with fallback placeholder during early rollout
try:  # pragma: no cover - exercised once real module exists
    from .base import AuthProvider  # type: ignore
except Exception:  # pragma: no cover

    class AuthProvider:  # type: ignore
        """Placeholder interface; replaced by real abstract base in Phase 0-2."""

        def verify_token(self, token: str) -> Dict[str, Any]:  # noqa: D401
            raise NotImplementedError("AuthProvider not implemented yet")

        def get_user_roles(self, uid: str) -> List[str]:  # noqa: D401
            raise NotImplementedError("AuthProvider not implemented yet")

        def healthcheck(self) -> Dict[str, Any]:
            return {"provider": "unknown", "status": "init"}


# Import mock provider with fallback placeholder
try:  # pragma: no cover - exercised once real module exists
    from .mock_auth0 import MockAuth0Provider  # type: ignore
except Exception:  # pragma: no cover

    class MockAuth0Provider:  # type: ignore
        """Placeholder mock provider; replaced by real implementation."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
            raise RuntimeError("MockAuth0Provider not implemented yet")


# Import Auth0 provider if available
try:  # pragma: no cover - exercised once real module exists
    from .auth0 import Auth0Provider  # type: ignore
except Exception:  # pragma: no cover

    class Auth0Provider:  # type: ignore
        def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
            raise RuntimeError("Auth0Provider not available")


def _require_str(cfg: Mapping[str, Any], key: str) -> str:
    val = cfg.get(key)
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"config[{key}] must be a non-empty string")
    return val.strip()


def _optional_int(cfg: Mapping[str, Any], key: str, default: int) -> int:
    val = cfg.get(key)
    if val is None:
        return int(default)
    try:
        return int(val)
    except Exception as exc:  # pragma: no cover - trivial branch
        raise ValueError(f"config[{key}] must be an integer") from exc


def build_auth0_provider(config: Mapping[str, Any]) -> "Auth0Provider":
    """Build an Auth0Provider from a simple config mapping.

    Required keys:
      - issuer: https URL of the Auth0 tenant (e.g., https://tenant.auth0.com/)
      - audience: expected API audience string

    Optional keys:
      - jwks_url, jwks_cache_ttl_s, jwks_timeout_s, clock_skew_s
    """
    try:
        issuer = _require_str(config, "issuer")
        audience = _require_str(config, "audience")
    except ValueError as e:
        logger.error(f"Invalid Auth0 config: {e}")
        raise

    if not issuer.startswith("https://"):
        logger.error("Invalid Auth0 issuer: must start with https://")
        raise ValueError("issuer must start with https://")

    jwks_url = config.get("jwks_url")
    if jwks_url is not None and (not isinstance(jwks_url, str) or not jwks_url.startswith("https://")):
        logger.error("Invalid jwks_url: must be https URL string")
        raise ValueError("jwks_url must be https URL string")

    jwks_cache_ttl_s = _optional_int(config, "jwks_cache_ttl_s", 3600)
    jwks_timeout_s = _optional_int(config, "jwks_timeout_s", 5)
    clock_skew_s = _optional_int(config, "clock_skew_s", 0)

    return Auth0Provider(
        issuer=issuer,
        audience=audience,
        jwks_url=jwks_url,
        jwks_cache_ttl_s=jwks_cache_ttl_s,
        jwks_timeout_s=jwks_timeout_s,
        clock_skew_s=clock_skew_s,
    )

