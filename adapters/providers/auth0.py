"""
Auth0 JWT provider with JWKS fetch, in-memory cache, and strict verification.

New location: adapters.providers.auth0
"""

from __future__ import annotations

import base64
import json
import random
import threading
import time
from typing import Any, Dict, List, Mapping, Optional

from jose import jwt
from jose.exceptions import JWTError

from adapters.providers.base import AuthProvider
from app_platform.utils.circuit_breaker import CircuitBreaker
from app_platform.rate_limit.metadata_limiter import rate_limit_metadata_fetch
from .auth0_jwks import JWKSClient
from .token_verifier import TokenVerifier


def _b64url_uint(data: int) -> str:
    length = (data.bit_length() + 7) // 8 or 1
    raw = data.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


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
        if not issuer or not audience:
            raise ValueError("issuer and audience are required")
        self.issuer = issuer.rstrip("/") + "/" if not issuer.endswith("/") else issuer
        self.audience = audience
        self.jwks_url = jwks_url or f"{self.issuer}.well-known/jwks.json"
        self.jwks_timeout_s = int(jwks_timeout_s)
        self.clock_skew_s = int(clock_skew_s)
        self._breaker = CircuitBreaker(
            failure_threshold=5,
            window_seconds=30,
            half_open_after_s=15,
            correlation_key_fn=lambda exc: getattr(exc, "__class__", type("")).__name__,
        )
        self._jwks = JWKSClient(url=self.jwks_url, timeout_s=self.jwks_timeout_s, cache_ttl_s=int(jwks_cache_ttl_s), breaker=self._breaker)
        self._jwks_cache = self._jwks._cache  # type: ignore[attr-defined]
        self._token_verifier = TokenVerifier()
        self._last_claims_by_sub: Dict[str, Mapping[str, Any]] = {}
        self._roles_cache_ttl_s = int(roles_cache_ttl_s)
        self._roles_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = threading.Lock()
        self._max_cache_entries = 4096

    def verify_token(self, token: str) -> Mapping[str, Any]:
        if not token or not isinstance(token, str):
            raise ValueError("token must be a non-empty string")

        try:
            header = jwt.get_unverified_header(token)
        except JWTError as exc:
            raise ValueError(f"invalid token header: {exc}") from exc

        alg = header.get("alg")
        if alg != "RS256":
            raise ValueError("unsupported alg; RS256 required")
        kid = header.get("kid")
        if not kid:
            raise ValueError("missing kid in token header")

        key = self._jwks.get_key(kid)
        if key is None or self._jwks_cache.is_expired():
            jwks = self._jwks.fetch_raw()
            kid_to_key = self._jwks.prepare_keys(jwks)
            self._jwks.set_all(kid_to_key)
            key = kid_to_key.get(kid)
            if key is None:
                raise ValueError("kid not found in JWKS")

        claims = self._token_verifier.verify(
            token=token,
            key=key,
            audience=self.audience,
            issuer=self.issuer,
            clock_skew_s=self.clock_skew_s,
        )

        sub = str(claims.get("sub", ""))
        if sub:
            self._last_claims_by_sub[sub] = dict(claims)
        return dict(claims)

    def get_user_roles(self, uid: str) -> List[str]:
        mgmt = getattr(self, "_management_client", None)
        if mgmt is not None:
            cached = self._roles_cache.get(uid)
            now_s = time.time()
            if isinstance(cached, dict):
                ts = cached.get("ts", 0.0)
                if now_s - float(ts) < self._roles_cache_ttl_s:
                    roles_cached = cached.get("roles", [])
                    if isinstance(roles_cached, list):
                        return [str(r) for r in roles_cached]

            try:
                current = mgmt.get_user_metadata(uid) or {}
                app_meta = current.get("app_metadata", {}) if isinstance(current, dict) else {}
                bas_roles = app_meta.get("bas_roles", {}) if isinstance(app_meta, dict) else {}
                version = bas_roles.get("version") if isinstance(bas_roles, dict) else None
                raw_roles = bas_roles.get("roles") if isinstance(bas_roles, dict) else None
                roles_list: List[str] = self._normalize_roles(raw_roles)

                if roles_list:
                    cached_ver = cached.get("version") if isinstance(cached, dict) else None
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
        with self._cache_lock:
            if not force:
                cached = self._roles_cache.get(uid)
                if cached and time.time() - cached['ts'] < self._roles_cache_ttl_s:
                    return cached
            if len(self._roles_cache) >= self._max_cache_entries:
                oldest = min(self._roles_cache, key=lambda k: self._roles_cache[k]['ts'])
                del self._roles_cache[oldest]
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
                if attempt == 2:
                    raise
                time.sleep(0.1 * (2 ** attempt))
        raise ValueError("Metadata lookup failed")

    def force_refresh(self, uid: str) -> None:
        self.cached_metadata_lookup(uid, force=True)

    def cache_bust_on_event(self, event_data: Dict[str, Any]) -> bool:
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
        roles: List[str] = []
        if isinstance(raw_roles, list):
            roles.extend([str(x) for x in raw_roles])
        elif isinstance(raw_roles, dict):
            for k, v in raw_roles.items():
                if v:
                    roles.append(str(k))
        seen = set()
        result: List[str] = []
        for r in roles:
            if r not in seen:
                seen.add(r)
                result.append(r)
        return result

    def _extract_roles_from_claims(self, claims: Mapping[str, Any]) -> List[str]:
        result: List[str] = []
        roles: List[str] = []
        for key in ("roles", "permissions"):
            value = claims.get(key)
            if isinstance(value, list):
                roles.extend([str(x) for x in value])
        for k, v in claims.items():
            if isinstance(k, str) and k.endswith("/roles") and isinstance(v, list):
                roles.extend([str(x) for x in v])
        seen = set()
        for r in roles:
            if r not in seen:
                seen.add(r)
                result.append(r)
        return result

    def healthcheck(self) -> Dict[str, Any]:
        return {
            "provider": "Auth0Provider",
            "status": "ok",
            "issuer": self.issuer,
            "audience": self.audience,
            "jwks_url": self.jwks_url,
            "jwks_age_s": round(self._jwks_cache.age_seconds(), 3),
        }

    def invalidate_cache(self) -> None:
        self._jwks_cache.clear()


