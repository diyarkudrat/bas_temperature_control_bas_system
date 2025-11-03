"""
Mock Auth0 provider implementing local RS256 JWT verification and static roles.

Used for development and testing.
"""

from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Mapping, Optional

from jose import jwt  # type: ignore[import]
from jose.exceptions import JWTError  # type: ignore[import]

try:  # key generation for dev mode only
    from cryptography.hazmat.primitives import serialization  # type: ignore[import]
    from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore[import]
    _CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover
    # Cryptography is not available, so we can't generate keys
    _CRYPTO_AVAILABLE = False

from adapters.providers.base import AuthProvider


class MockAuth0Provider(AuthProvider):
    """Local RS256 JWT verification with static role mapping."""

    def __init__(
        self,
        *,
        audience: str = "bas-api",
        issuer: str = "https://mock.auth0/",
        roles_map: Optional[Dict[str, List[str]]] = None,
        public_key_pem: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        clock_skew_s: int = 0,
        roles_cache_ttl_s: int = 60,
    ) -> None:
        """Initialize the MockAuth0 provider."""

        self._audience = audience
        self._issuer = issuer
        self._roles_map: Dict[str, List[str]] = roles_map or {}
        self._clock_skew_s = int(clock_skew_s)
        self._roles_cache_ttl_s = int(roles_cache_ttl_s)
        self._roles_meta: Dict[str, Dict[str, Any]] = {}
        self._roles_cache: Dict[str, Dict[str, Any]] = {}

        # Failure injection counters (for tests)
        self._inject_fail_next_get: int = 0
        self._inject_fail_next_set: int = 0
        self._inject_conflict_next_set: int = 0

        self._private_key_pem: Optional[str] = private_key_pem
        self._public_key_pem: Optional[str] = public_key_pem
        self._mode = "provided" if (public_key_pem or private_key_pem) else "generated"

        if self._public_key_pem is None:
            if not _CRYPTO_AVAILABLE:
                self._mode = "no-crypto"
            else:
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                self._private_key_pem = (
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    ).decode("utf-8")
                )
                self._public_key_pem = (
                    private_key.public_key()
                    .public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    .decode("utf-8")
                )

    @property
    def public_key_pem(self) -> Optional[str]:
        """Get the public key in PEM format."""

        return self._public_key_pem

    @property
    def private_key_pem(self) -> Optional[str]:
        """Get the private key in PEM format."""

        return self._private_key_pem

    @property
    def audience(self) -> str:
        """Audience that minted tokens must target."""

        return self._audience

    @property
    def issuer(self) -> str:
        """Issuer value embedded in minted tokens."""

        return self._issuer

    @property
    def clock_skew_s(self) -> int:
        """Clock skew allowance in seconds."""

        return self._clock_skew_s

    @property
    def roles_map(self) -> Dict[str, List[str]]:
        """Read-only view of the static roles mapping."""

        return {uid: list(roles) for uid, roles in self._roles_map.items()}

    def verify_token(self, token: str) -> Mapping[str, Any]:
        """Verify a token and return the claims."""

        if not self._public_key_pem:
            raise ValueError("MockAuth0Provider has no public key available for verification")

        try:
            claims = jwt.decode(
                token,
                self._public_key_pem,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
                leeway=self._clock_skew_s,
            )
        except JWTError as exc:
            raise ValueError(f"invalid token: {exc}") from exc

        return dict[str, Any](claims)

    def get_user_roles(self, uid: str) -> List[str]:
        """Get the user roles."""

        if self._inject_fail_next_get > 0:
            self._inject_fail_next_get -= 1
            raise RuntimeError("injected read failure")

        now_s = time.time()
        cached = self._roles_cache.get(uid)
        if isinstance(cached, dict):
            ts = cached.get("ts", 0.0)
            if now_s - float(ts) < self._roles_cache_ttl_s:
                roles_cached = cached.get("roles", [])
                if isinstance(roles_cached, list):
                    return list(roles_cached)

        meta = self._roles_meta.get(uid)
        if isinstance(meta, dict) and isinstance(meta.get("roles"), list):
            roles_list = list(meta["roles"])  # copy
            self._roles_cache[uid] = {"roles": roles_list, "version": meta.get("version"), "ts": now_s}
            return roles_list

        return list(self._roles_map.get(uid, []))

    def inject_failure(self, *, get: int = 0, set: int = 0, conflict: int = 0) -> None:
        """Inject a failure."""

        self._inject_fail_next_get = int(get)
        self._inject_fail_next_set = int(set)
        self._inject_conflict_next_set = int(conflict)

    def set_user_roles(
        self,
        user_id: str,
        roles: Mapping[str, Any],
        *,
        max_retries: int = 0,
        initial_backoff_s: float = 0.0,
    ) -> Dict[str, Any]:
        """Set the user roles."""

        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        if not isinstance(roles, Mapping):
            raise ValueError("roles must be a mapping")

        attempt = 0
        backoff = float(initial_backoff_s)
        last_error: Optional[Exception] = None

        def _jitter(delay: float) -> float:
            """Jitter the delay."""

            return delay * (0.5 + random.random()) if delay > 0 else 0.0

        while attempt <= max_retries:
            attempt += 1

            try:
                if self._inject_conflict_next_set > 0:
                    self._inject_conflict_next_set -= 1
                    exc = RuntimeError("conflict")
                    setattr(exc, "status_code", 409)
                    raise exc
                if self._inject_fail_next_set > 0:
                    self._inject_fail_next_set -= 1
                    exc = RuntimeError("transient failure")
                    setattr(exc, "status_code", 503)
                    raise exc

                current_ver = 0
                meta = self._roles_meta.get(user_id)
                if isinstance(meta, dict) and isinstance(meta.get("version"), int):
                    current_ver = int(meta["version"])

                new_ver = current_ver + 1
                roles_list: List[str] = []

                for k, v in roles.items():
                    if v:
                        roles_list.append(str(k))

                self._roles_meta[user_id] = {"version": new_ver, "roles": roles_list, "updated_at_ms": int(time.time() * 1000)}
                self._roles_cache[user_id] = {"version": new_ver, "roles": list[str](roles_list), "ts": time.time()}
                self._roles_map[user_id] = list[str](roles_list)

                return {"app_metadata": {"bas_roles": {"version": new_ver, "roles": list[str](roles_list)}}}
            except Exception as exc:
                last_error = exc

                if attempt > max_retries:
                    raise ValueError(f"failed to set roles for {user_id}: {exc}") from exc

                time.sleep(_jitter(backoff))
                backoff = min(backoff * 2.0 if backoff > 0 else 0.05, 1.0)

        raise ValueError(f"failed to set roles for {user_id}: {last_error}")

    def healthcheck(self) -> Dict[str, Any]:
        """Healthcheck the provider."""

        now_ms = int(time.monotonic() * 1000)

        return {
            "provider": "MockAuth0Provider",
            "status": "ok",
            "now_epoch_ms": now_ms,
            "mode": "mock",
            "alg": "RS256",
            "key_mode": self._mode,
            "has_private_key": bool(self._private_key_pem),
        }


