"""
Auth0 JWT provider with JWKS fetch, in-memory cache, and strict verification.

New location: adapters.providers.auth0
"""

from __future__ import annotations

import base64
import threading
import time
from typing import Any, Dict, List, Mapping, Optional

from jose import jwt  # type: ignore[import]
from jose.exceptions import JWTError  # type: ignore[import]

from adapters.providers.base import AuthProvider
from app_platform.utils.circuit_breaker import CircuitBreaker
from app_platform.rate_limit.metadata_limiter import rate_limit_metadata_fetch
from .auth0_jwks import JWKSClient
from .token_verifier import TokenVerifier


class Auth0Provider(AuthProvider):
    """Auth0 JWT verification using JWKS.

    - RS256 only
    - Requires matching audience and issuer
    - Uses JWKS endpoint with timeout and TTL caching
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: Optional[str] = None,
        jwks_cache_ttl_s: int = 3600,
        jwks_timeout_s: int = 5,
        clock_skew_s: int = 0,
        roles_cache_ttl_s: int = 60,
    ) -> None:
        """Initialize the Auth0 provider."""

        if not issuer or not audience:
            raise ValueError("issuer and audience are required")
        if not audience or not isinstance(audience, str):
            raise ValueError("audience must be a non-empty string")

        normalized_issuer = issuer.rstrip("/") + "/" if not issuer.endswith("/") else issuer
        self._issuer = normalized_issuer  # Normalize issuer URL once and keep private
        self._audience = audience  # Audience to verify against
        self._jwks_url = jwks_url or f"{normalized_issuer}.well-known/jwks.json"  # Default JWKS URL if not provided
        self._jwks_timeout_s = int(jwks_timeout_s)  # Timeout in seconds
        self._clock_skew_s = int(clock_skew_s)  # Clock skew in seconds
        self._breaker = CircuitBreaker(
            failure_threshold=5,
            window_seconds=30,
            half_open_after_s=15,
            correlation_key_fn=lambda exc: getattr(exc, "__class__", type("")).__name__,
        ) # Circuit breaker for JWKS fetch
        self._jwks = JWKSClient(url=self._jwks_url, timeout_s=self._jwks_timeout_s, cache_ttl_s=int(jwks_cache_ttl_s), breaker=self._breaker) # JWKS client
        self._token_verifier = TokenVerifier() # Token verifier
        self._last_claims_by_sub: Dict[str, Mapping[str, Any]] = {} # Last claims by subject
        self._roles_cache_ttl_s = int(roles_cache_ttl_s) # Roles cache TTL in seconds
        self._roles_cache: Dict[str, Dict[str, Any]] = {} # Roles cache
        self._cache_lock = threading.Lock() # Cache lock
        self._max_cache_entries = 4096 # Max cache entries

    @property
    def issuer(self) -> str:
        """Issuer URL configured for this provider."""

        return self._issuer

    @property
    def audience(self) -> str:
        """Audience that incoming tokens must target."""

        return self._audience

    @property
    def jwks_url(self) -> str:
        """JWKS endpoint URL used for key retrieval."""

        return self._jwks_url

    @property
    def jwks_timeout_s(self) -> int:
        """HTTP timeout (seconds) for JWKS fetches."""

        return self._jwks_timeout_s

    @property
    def clock_skew_s(self) -> int:
        """Allowed clock skew (seconds) when validating tokens."""

        return self._clock_skew_s

    def verify_token(self, token: str) -> Mapping[str, Any]:
        """Verify a token and return the claims."""

        if not token or not isinstance(token, str):
            raise ValueError("token must be a non-empty string")

        try:
            header = jwt.get_unverified_header(token)
        except JWTError as exc:
            raise ValueError(f"invalid token header: {exc}") from exc

        alg = header.get("alg") # Algorithm
        if alg != "RS256":
            raise ValueError("unsupported alg; RS256 required")

        kid = header.get("kid") # Key ID
        if not kid:
            raise ValueError("missing kid in token header")

        key = self._jwks.get_key(kid)

        if key is None or self._jwks.is_expired():
            jwks = self._jwks.fetch_raw()

            kid_to_key = self._jwks.prepare_keys(jwks)
            self._jwks.set_all(kid_to_key)

            key = kid_to_key.get(kid)

            if key is None:
                raise ValueError("kid not found in JWKS")

        claims = self._token_verifier.verify(
            token=token,
            key=key,
        audience=self._audience,
        issuer=self._issuer,
        clock_skew_s=self._clock_skew_s,
        )

        sub = str(claims.get("sub", "")) # Subject
        if sub:
            self._last_claims_by_sub[sub] = dict(claims)

        return dict[str, Any](claims)

    def get_user_roles(self, uid: str) -> List[str]:
        """Get the user roles."""

        if not uid or not isinstance(uid, str):
            raise ValueError("uid must be a non-empty string")
        
        mgmt = getattr(self, "_management_client", None)

        if mgmt is not None:
            cached = self._roles_cache.get(uid)
            now_s = time.monotonic()

            if isinstance(cached, dict):
                ts = cached.get("ts", 0.0) # Timestamp
                
                # Check if the cache is expired
            if now_s - float(ts) < self._roles_cache_ttl_s:
                    roles_cached = cached.get("roles", [])

                    if isinstance(roles_cached, list):
                        return [str(r) for r in roles_cached]

            try:
                current = mgmt.get_user_metadata(uid) or {} # Get the user metadata

                app_meta = current.get("app_metadata", {}) if isinstance(current, dict) else {}
                bas_roles = app_meta.get("bas_roles", {}) if isinstance(app_meta, dict) else {}
                version = bas_roles.get("version") if isinstance(bas_roles, dict) else None

                raw_roles = bas_roles.get("roles") if isinstance(bas_roles, dict) else None
                roles_list: List[str] = self._normalize_roles(raw_roles)

                if roles_list:
                    cached_ver = cached.get("version") if isinstance(cached, dict) else None

                    # Check if the version is different
                    if isinstance(version, int) and version != cached_ver:
                        self._roles_cache[uid] = {"version": version, "roles": roles_list, "ts": now_s}
                    else:
                        self._roles_cache[uid] = {
                            "version": (version if isinstance(version, int) else cached_ver),
                            "roles": roles_list,
                            "ts": now_s,
                        }

                if roles_list:
                    return roles_list

            except Exception:
                if isinstance(cached, dict):
                    roles_cached = cached.get("roles", [])

                    if isinstance(roles_cached, list) and roles_cached:
                        return [str(r) for r in roles_cached]

        claims = self._last_claims_by_sub.get(uid)

        return self._extract_roles_from_claims(claims) if claims else []

    def cached_metadata_lookup(self, uid: str, force: bool = False) -> Dict[str, Any]:
        """Cached metadata lookup."""

        if not uid or not isinstance(uid, str):
            raise ValueError("uid must be a non-empty string")

        with self._cache_lock:
            if not force:
                cached = self._roles_cache.get(uid)

                # Check if the cache is not expired
                if cached and time.monotonic() - cached['ts'] < self._roles_cache_ttl_s:
                    return cached
                    
            # Check if the cache is full
            if len(self._roles_cache) >= self._max_cache_entries:
                oldest = min(self._roles_cache, key=lambda k: self._roles_cache[k]['ts'])

                del self._roles_cache[oldest]

        # Try to get the metadata
        for attempt in range(3):
            try:
                allowed, backoff = rate_limit_metadata_fetch(uid)

                if not allowed:
                    time.sleep(backoff)

                current = self._management_client.get_user_metadata(uid) or {}
                with self._cache_lock:
                    self._roles_cache[uid] = {'meta': current, 'ts': time.time()}

                return current
            except Exception as e:
                # If the attempt is the last one, raise the exception
                if attempt == 2:
                    raise
                time.sleep(0.1 * (2 ** attempt))

        raise ValueError("Metadata lookup failed")

    def force_refresh(self, uid: str) -> None:
        """Force refresh the metadata."""

        if not uid or not isinstance(uid, str):
            raise ValueError("uid must be a non-empty string")

        self.cached_metadata_lookup(uid, force=True)

    def cache_bust_on_event(self, event_data: Dict[str, Any]) -> bool:
        """Cache bust on event."""

        if not event_data or not isinstance(event_data, dict):
            raise ValueError("event_data must be a non-empty dictionary")

        uid = event_data.get('user_id')

        if uid:
            with self._cache_lock:
                if uid in self._roles_cache:
                    del self._roles_cache[uid]

            try:
                self.force_refresh(uid)

                return True
            except Exception:
                return False

        return False

    def _normalize_roles(self, raw_roles: Any) -> List[str]:
        """Normalize the roles."""

        if not raw_roles or not isinstance(raw_roles, (list, dict)):
            raise ValueError("raw_roles must be a list or dictionary")

        roles: List[str] = []
        if isinstance(raw_roles, list):
            roles.extend([str(x) for x in raw_roles])

        elif isinstance(raw_roles, dict):
            for k, v in raw_roles.items():
                if v:
                    roles.append(str(k))

        seen = set[Any]()
        result: List[str] = []

        for r in roles:
            if r not in seen:
                seen.add(r)
                result.append(r)

        return result

    def _extract_roles_from_claims(self, claims: Mapping[str, Any]) -> List[str]:
        """Extract the roles from the claims."""

        if not claims or not isinstance(claims, dict):
            raise ValueError("claims must be a non-empty dictionary")

        result: List[str] = []
        roles: List[str] = []

        # Extract the roles from the claims
        for key in ("roles", "permissions"):
            value = claims.get(key)

            if isinstance(value, list):
                roles.extend([str(x) for x in value])

        for k, v in claims.items():
            # Extract the roles from the claims
            if isinstance(k, str) and k.endswith("/roles") and isinstance(v, list):
                roles.extend([str(x) for x in v])

        seen = set[Any]()
        for r in roles:
            if r not in seen:
                seen.add(r)
                result.append(r)

        return result

    def healthcheck(self) -> Dict[str, Any]:
        """Healthcheck the provider."""

        return {
            "provider": "Auth0Provider",
            "status": "ok",
            "issuer": self._issuer,
            "audience": self._audience,
            "jwks_url": self._jwks_url,
            "jwks_age_s": round(self._jwks.age_seconds(), 3),
        }

    def invalidate_cache(self) -> None:
        """Invalidate the cache."""

        self._jwks.invalidate()