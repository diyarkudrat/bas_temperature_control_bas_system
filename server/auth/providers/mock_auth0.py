"""
Mock Auth0 provider implementing local RS256 JWT verification and static roles.

This provider performs no network I/O and is suitable for tests and demos.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Mapping, Optional
import random

from jose import jwt
from jose.exceptions import JWTError

try:  # key generation for dev mode only
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    _CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover
    _CRYPTO_AVAILABLE = False

from .base import AuthProvider


class MockAuth0Provider(AuthProvider):
    """Local RS256 JWT verification with static role mapping.

    - Generates an ephemeral RSA key pair if none is provided (dev/demo only)
    - Verifies tokens against the configured audience and issuer
    - Provides a simple uid→roles mapping without I/O
    """

    def __init__(
        self,
        audience: str = "bas-api",
        issuer: str = "https://mock.auth0/",
        roles_map: Optional[Dict[str, List[str]]] = None,
        public_key_pem: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        clock_skew_s: int = 0,
        roles_cache_ttl_s: int = 60,
    ) -> None:
        self.audience = audience
        self.issuer = issuer
        self.roles_map: Dict[str, List[str]] = roles_map or {}
        self.clock_skew_s = int(clock_skew_s)
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
            # Generate an ephemeral dev key pair if not provided
            if not _CRYPTO_AVAILABLE:
                # Defer failure until verification is attempted
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

    # Public helpers for tests/utilities (not part of interface)
    @property
    def public_key_pem(self) -> Optional[str]:
        return self._public_key_pem

    @property
    def private_key_pem(self) -> Optional[str]:
        return self._private_key_pem

    def verify_token(self, token: str) -> Mapping[str, Any]:
        if not self._public_key_pem:
            raise ValueError("MockAuth0Provider has no public key available for verification")

        try:
            claims = jwt.decode(
                token,
                self._public_key_pem,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
                leeway=self.clock_skew_s,
            )
        except JWTError as exc:
            raise ValueError(f"invalid token: {exc}") from exc

        # Return as an immutable mapping view
        return dict(claims)

    def get_user_roles(self, uid: str) -> List[str]:
        # Failure injection: simulate transient read failure
        if self._inject_fail_next_get > 0:
            self._inject_fail_next_get -= 1
            raise RuntimeError("injected read failure")

        # Serve from cache if fresh
        now_s = time.time()
        cached = self._roles_cache.get(uid)
        if isinstance(cached, dict):
            ts = cached.get("ts", 0.0)
            if now_s - float(ts) < self._roles_cache_ttl_s:
                roles_cached = cached.get("roles", [])
                if isinstance(roles_cached, list):
                    return list(roles_cached)

        # Use versioned metadata if present; otherwise fallback to roles_map
        meta = self._roles_meta.get(uid)
        if isinstance(meta, dict) and isinstance(meta.get("roles"), list):
            roles_list = list(meta["roles"])  # copy
            self._roles_cache[uid] = {"roles": roles_list, "version": meta.get("version"), "ts": now_s}
            return roles_list

        return list(self.roles_map.get(uid, []))

    # Test helper to inject failures
    def inject_failure(self, *, get: int = 0, set: int = 0, conflict: int = 0) -> None:
        self._inject_fail_next_get = int(get)
        self._inject_fail_next_set = int(set)
        self._inject_conflict_next_set = int(conflict)

    # Local role management with retry to emulate distributed tx behavior
    def set_user_roles(
        self,
        user_id: str,
        roles: Mapping[str, Any],
        *,
        max_retries: int = 0,
        initial_backoff_s: float = 0.0,
    ) -> Dict[str, Any]:
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        if not isinstance(roles, Mapping):
            raise ValueError("roles must be a mapping")

        attempt = 0
        backoff = float(initial_backoff_s)
        last_error: Optional[Exception] = None

        def _jitter(delay: float) -> float:
            return delay * (0.5 + random.random()) if delay > 0 else 0.0

        while attempt <= max_retries:
            attempt += 1
            try:
                # Failure injection: conflict takes precedence over generic failure
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

                # Versioned update in memory
                current_ver = 0
                meta = self._roles_meta.get(user_id)
                if isinstance(meta, dict) and isinstance(meta.get("version"), int):
                    current_ver = int(meta["version"])
                new_ver = current_ver + 1
                roles_list: List[str] = []
                for k, v in roles.items():
                    if v:
                        roles_list.append(str(k))
                # Update meta, cache, and compatibility roles_map
                self._roles_meta[user_id] = {"version": new_ver, "roles": roles_list, "updated_at_ms": int(time.time() * 1000)}
                self._roles_cache[user_id] = {"version": new_ver, "roles": list(roles_list), "ts": time.time()}
                self.roles_map[user_id] = list(roles_list)
                return {"app_metadata": {"bas_roles": {"version": new_ver, "roles": list(roles_list)}}}
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if attempt > max_retries:
                    raise ValueError(f"failed to set roles for {user_id}: {exc}") from exc
                time.sleep(_jitter(backoff))
                backoff = min(backoff * 2.0 if backoff > 0 else 0.05, 1.0)
        # Should not reach here
        raise ValueError(f"failed to set roles for {user_id}: {last_error}")

    def healthcheck(self) -> Dict[str, Any]:
        now_ms = int(time.time() * 1000)
        return {
            "provider": "MockAuth0Provider",
            "status": "ok",
            "now_epoch_ms": now_ms,
            "mode": "mock",
            "alg": "RS256",
            "key_mode": self._mode,
            "has_private_key": bool(self._private_key_pem),
        }


