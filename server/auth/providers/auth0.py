"""
Auth0 JWT provider with JWKS fetch, in-memory cache, and strict verification.

Design goals (Phase 1):
- Fail-closed verification: RS256 only, audience and issuer required
- JWKS cache with TTL to mitigate downtime; bounded memory footprint
- Timeouts on network calls; no retries here (caller may implement)
"""

from __future__ import annotations

import base64
import json
import random
import threading
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

from jose import jwk, jwt
from jose.exceptions import JWTError, JWKError

try:  # stdlib HTTP with timeout to avoid extra deps
    from urllib.request import urlopen
    from urllib.error import URLError, HTTPError
except Exception:  # pragma: no cover
    urlopen = None  # type: ignore
    URLError = Exception  # type: ignore
    HTTPError = Exception  # type: ignore

from .base import AuthProvider


def _b64url_uint(data: int) -> str:
    """Encode an int to base64url without padding."""
    # Convert int to big-endian bytes without leading zeros
    length = (data.bit_length() + 7) // 8 or 1
    raw = data.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class _JwksCache:
    """Thread-safe JWKS cache keyed by KID.

    Stores prepared jose.jwk keys. Not intended for cross-process sharing.
    """

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = int(ttl_seconds)
        self._keys: Dict[str, Any] = {}
        self._fetched_at: float = 0.0
        self._lock = threading.Lock()

    def is_expired(self) -> bool:
        with self._lock:
            if self._fetched_at <= 0:
                return True
            return (time.time() - self._fetched_at) >= self._ttl

    def get(self, kid: str) -> Optional[Any]:
        with self._lock:
            return self._keys.get(kid)

    def set_all(self, kid_to_key: Dict[str, Any]) -> None:
        with self._lock:
            self._keys = dict(kid_to_key)
            self._fetched_at = time.time()

    def clear(self) -> None:
        with self._lock:
            self._keys.clear()
            self._fetched_at = 0.0

    def age_seconds(self) -> float:
        with self._lock:
            if self._fetched_at <= 0:
                return float("inf")
            return max(0.0, time.time() - self._fetched_at)


class Auth0Provider(AuthProvider):
    """Auth0 JWT verification using JWKS.

    - RS256 only
    - Requires matching audience and issuer
    - Uses JWKS endpoint with timeout and TTL caching
    """

    def __init__(
        self,
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
        self._jwks_cache = _JwksCache(int(jwks_cache_ttl_s))
        # Minimal last-claims cache to support get_user_roles until a real RBAC source exists
        self._last_claims_by_sub: Dict[str, Mapping[str, Any]] = {}
        # Roles cache seeded from management metadata with versioning
        self._roles_cache_ttl_s = int(roles_cache_ttl_s)
        self._roles_cache: Dict[str, Dict[str, Any]] = {}

    # -------------------------- Public API --------------------------
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

        key = self._jwks_cache.get(kid)
        if key is None or self._jwks_cache.is_expired():
            jwks = self._fetch_jwks()
            kid_to_key = self._prepare_keys(jwks)
            self._jwks_cache.set_all(kid_to_key)
            key = kid_to_key.get(kid)
            if key is None:
                raise ValueError("kid not found in JWKS")

        try:
            claims = jwt.decode(
                token,
                key.to_pem().decode("utf-8"),
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_iat": True,
                    "verify_exp": True,
                },
                leeway=self.clock_skew_s,
            )
        except JWTError as exc:
            raise ValueError(f"invalid token: {exc}") from exc

        # Cache recent claims per subject for lightweight role access helpers
        sub = str(claims.get("sub", ""))
        if sub:
            self._last_claims_by_sub[sub] = dict(claims)
        return dict(claims)

    def get_user_roles(self, uid: str) -> List[str]:
        # If a management client is configured, use versioned metadata with caching
        mgmt = getattr(self, "_management_client", None)
        if mgmt is not None:
            # Serve from cache if fresh
            cached = self._roles_cache.get(uid)
            now_s = time.time()
            if isinstance(cached, dict):
                ts = cached.get("ts", 0.0)
                if now_s - float(ts) < self._roles_cache_ttl_s:
                    roles_cached = cached.get("roles", [])
                    if isinstance(roles_cached, list):
                        return [str(r) for r in roles_cached]

            # Refresh from management metadata
            try:
                current = mgmt.get_user_metadata(uid) or {}
                app_meta = current.get("app_metadata", {}) if isinstance(current, dict) else {}
                bas_roles = app_meta.get("bas_roles", {}) if isinstance(app_meta, dict) else {}
                version = bas_roles.get("version") if isinstance(bas_roles, dict) else None
                raw_roles = bas_roles.get("roles") if isinstance(bas_roles, dict) else None
                roles_list: List[str] = self._normalize_roles(raw_roles)

                # Update cache only if we have roles info
                if roles_list:
                    cached_ver = cached.get("version") if isinstance(cached, dict) else None
                    if isinstance(version, int) and version != cached_ver:
                        self._roles_cache[uid] = {"version": version, "roles": roles_list, "ts": now_s}
                    else:
                        # No version info or unchanged: still refresh timestamp
                        self._roles_cache[uid] = {
                            "version": (version if isinstance(version, int) else cached_ver),
                            "roles": roles_list,
                            "ts": now_s,
                        }
                if roles_list:
                    return roles_list
            except Exception:
                # On management errors, fall back to any cached value if available
                if isinstance(cached, dict):
                    roles_cached = cached.get("roles", [])
                    if isinstance(roles_cached, list) and roles_cached:
                        return [str(r) for r in roles_cached]
                # Otherwise fall through to claims

        # Claims-based fallback
        claims = self._last_claims_by_sub.get(uid)
        return self._extract_roles_from_claims(claims) if claims else []

    def _normalize_roles(self, raw_roles: Any) -> List[str]:
        roles: List[str] = []
        if isinstance(raw_roles, list):
            roles.extend([str(x) for x in raw_roles])
        elif isinstance(raw_roles, dict):
            # For mapping, treat keys as role names when truthy
            for k, v in raw_roles.items():
                if v:
                    roles.append(str(k))
        # De-duplicate while preserving order
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

    # -------------------------- Utilities --------------------------
    def invalidate_cache(self) -> None:
        self._jwks_cache.clear()

    # ------------------------ Role Management ------------------------
    # Helper utilities to keep set_user_roles readable
    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def _jitter(self, delay: float) -> float:
        return delay * (0.5 + random.random())

    def _is_retryable_error(self, err: Exception) -> bool:
        result = False

        status = getattr(err, "status_code", None)
        code = getattr(err, "code", None)
        if isinstance(status, int):
            if status in (409, 429):
                result = True
            if 500 <= status < 600:
                result = True
        if isinstance(code, str) and code.lower() in {"conflict", "rate_limit", "timeout", "etimedout"}:
            result = True
        text = str(err).lower()
        for needle in ("timeout", "temporarily unavailable", "connection reset", "conflict"):
            if needle in text:
                result = True
                
        return result

    def _get_mgmt_client(self, management_client: Optional[Any]) -> Any:
        mgmt = management_client
        if mgmt is None and hasattr(self, "_management_client"):
            mgmt = getattr(self, "_management_client")
        if mgmt is None:
            raise NotImplementedError("management client not configured for role updates")
        return mgmt

    def _read_current_version(self, mgmt: Any, user_id: str) -> Optional[int]:
        current = mgmt.get_user_metadata(user_id) or {}
        app_meta = current.get("app_metadata", {}) if isinstance(current, dict) else {}
        bas_roles = app_meta.get("bas_roles", {}) if isinstance(app_meta, dict) else {}
        version = bas_roles.get("version") if isinstance(bas_roles, dict) else None
        return version if isinstance(version, int) else None

    def _build_roles_payload(self, roles: Mapping[str, Any], new_version: int) -> Dict[str, Any]:
        return {
            "app_metadata": {
                "bas_roles": {
                    "roles": dict(roles),
                    "version": int(new_version),
                    "updated_at_ms": self._now_ms(),
                }
            }
        }

    def _generate_idempotency_key(self, user_id: str) -> str:
        return f"bas-set-roles-{user_id}-{self._now_ms()}-{random.randint(0, 1_000_000)}"

    def set_user_roles(
        self,
        user_id: str,
        roles: Mapping[str, Any],
        *,
        max_retries: int = 3,
        initial_backoff_s: float = 0.05,
        management_client: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Set roles for a user with simple CAS (compare-and-swap) and retry semantics.

        Distributed transaction support: performs a read-then-CAS update using a
        version field in app_metadata to avoid lost updates. Retries on common
        transient errors (HTTP 409/429/5xx) with exponential backoff + jitter.

        management_client API (duck-typed for tests):
          - get_user_metadata(user_id) -> {"app_metadata": {...}} or {}
          - update_user_metadata(user_id, payload, expected_version: Optional[int], idempotency_key: str) -> dict
        """
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        if not isinstance(roles, Mapping):
            raise ValueError("roles must be a mapping")

        mgmt = self._get_mgmt_client(management_client)

        attempt = 0
        backoff = float(initial_backoff_s)
        last_error: Optional[Exception] = None

        while attempt <= max_retries:
            attempt += 1
            try:
                version = self._read_current_version(mgmt, user_id)
                new_version = (version + 1) if isinstance(version, int) else 1
                payload = self._build_roles_payload(roles, new_version)
                idem_key = self._generate_idempotency_key(user_id)
                updated = mgmt.update_user_metadata(
                    user_id,
                    payload,
                    expected_version=(version if isinstance(version, int) else None),
                    idempotency_key=idem_key,
                )
                # Best-effort: return updated snapshot
                if isinstance(updated, dict):
                    return updated
                return {"app_metadata": {"bas_roles": payload["app_metadata"]["bas_roles"]}}
            except Exception as exc:  # noqa: BLE001 - intentional catch for retry filter
                last_error = exc
                if attempt > max_retries or not self._is_retryable_error(exc):
                    raise ValueError(f"failed to set roles for {user_id}: {exc}") from exc
                time.sleep(self._jitter(backoff))
                backoff = min(backoff * 2.0, 1.0)

    def _fetch_jwks(self) -> Dict[str, Any]:
        if urlopen is None:
            raise ValueError("HTTP client unavailable for JWKS fetch")
        try:
            with urlopen(self.jwks_url, timeout=self.jwks_timeout_s) as resp:
                body = resp.read()
                data = json.loads(body.decode("utf-8"))
                if not isinstance(data, dict) or "keys" not in data:
                    raise ValueError("malformed JWKS document")
                return data
        except (URLError, HTTPError) as exc:
            raise ValueError(f"failed to fetch JWKS: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError("failed to parse JWKS JSON") from exc

    def _prepare_keys(self, jwks: Mapping[str, Any]) -> Dict[str, Any]:
        kid_to_key: Dict[str, Any] = {}
        keys = jwks.get("keys")
        if not isinstance(keys, list):
            raise ValueError("JWKS keys must be a list")
        for key_dict in keys:
            if not isinstance(key_dict, dict):
                continue
            kty = key_dict.get("kty")
            alg = key_dict.get("alg")
            kid = key_dict.get("kid")
            use = key_dict.get("use")
            if kty != "RSA" or (alg and alg != "RS256"):
                continue
            if use and use != "sig":
                continue
            if not kid:
                continue
            try:
                key = jwk.construct(key_dict, algorithm="RS256")
            except (JWKError, Exception):
                # Attempt to adapt if only n/e provided
                n = key_dict.get("n")
                e = key_dict.get("e")
                if not (isinstance(n, str) and isinstance(e, str)):
                    continue
                try:
                    key = jwk.construct({"kty": "RSA", "n": n, "e": e}, algorithm="RS256")
                except Exception:
                    continue
            kid_to_key[str(kid)] = key
        if not kid_to_key:
            raise ValueError("no usable RSA keys in JWKS")
        return kid_to_key


