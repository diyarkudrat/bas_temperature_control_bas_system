"""Service-to-service JWT helpers with asymmetric signing and replay protection."""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, MutableMapping, Optional, Sequence

try:
    from jose import jwt  # type: ignore[import]
    from jose.exceptions import ExpiredSignatureError, JWTError  # type: ignore[import]
except ImportError as exc:  # pragma: no cover - dependency validation
    raise ImportError(
        "python-jose[cryptography] is required for service JWT support"
    ) from exc

from .metrics import security_metrics

__all__ = [
    "ServiceKey",
    "ServiceKeySet",
    "ReplayCache",
    "IssuedServiceToken",
    "ServiceTokenError",
    "ServiceTokenValidationError",
    "issue_service_jwt",
    "verify_service_jwt",
    "build_auth_headers",
    "load_service_keyset_from_env",
    "load_replay_cache_from_env",
]


logger = logging.getLogger(__name__)

_DEFAULT_ALLOWED_ALGORITHMS = ("RS256", "ES256")
_DEFAULT_TOKEN_TTL_SECONDS = 60
_DEFAULT_REPLAY_TTL_SECONDS = 120
_DEFAULT_LOCAL_CACHE_SIZE = 4096

_METRIC_REPLAY_CACHE_REDIS_STORE = "service_jwt.replay_cache.redis_store"
_METRIC_REPLAY_CACHE_REDIS_HIT = "service_jwt.replay_cache.redis_hit"
_METRIC_REPLAY_CACHE_REDIS_ERROR = "service_jwt.replay_cache.redis_error"
_METRIC_REPLAY_CACHE_LOCAL_STORE = "service_jwt.replay_cache.local_store"
_METRIC_REPLAY_CACHE_LOCAL_HIT = "service_jwt.replay_cache.local_hit"
_METRIC_REPLAY_CACHE_LOCAL_EVICT = "service_jwt.replay_cache.local_evict"


class ServiceTokenError(Exception):
    """Base exception for service token helpers."""


class ServiceTokenValidationError(ServiceTokenError):
    """Raised when a service token fails validation."""


@dataclass(slots=True)
class ServiceKey:
    """Represents a single signing/verification key for service JWTs."""

    kid: str
    alg: str
    private_key: Optional[str] = None
    public_key: Optional[Any] = None
    use: str = "sig"
    not_before: Optional[int] = None
    expires_at: Optional[int] = None

    def ensure_signing_material(self) -> str:
        """Return the private key, raising if signing is not possible."""

        if not self.private_key:
            raise ServiceTokenError(f"private key not configured for kid={self.kid}")
        return _normalize_pem(self.private_key)

    def verification_material(self) -> Any:
        """Return material suitable for verification (public key or JWK)."""

        if self.public_key is not None:
            if isinstance(self.public_key, str):
                return _normalize_pem(self.public_key)
            return self.public_key
        if self.private_key is not None:
            return _normalize_pem(self.private_key)
        raise ServiceTokenError(f"no verification material available for kid={self.kid}")

    def header(self) -> Mapping[str, str]:
        """Return JWT header fragment for this key."""

        return {"kid": self.kid, "alg": self.alg, "typ": "JWT"}


class ServiceKeySet:
    """Collection of service keys with helpers for signing and verification."""

    def __init__(
        self,
        keys: Iterable[ServiceKey],
        *,
        default_kid: Optional[str] = None,
        allowed_algorithms: Optional[Sequence[str]] = None,
    ) -> None:
        key_list = list(keys)
        if not key_list:
            raise ServiceTokenError("service key set cannot be empty")

        self._keys: dict[str, ServiceKey] = {key.kid: key for key in key_list}
        if len(self._keys) != len(key_list):
            raise ServiceTokenError("duplicate key identifiers detected in key set")

        if default_kid is not None and default_kid not in self._keys:
            raise ServiceTokenError(f"default kid '{default_kid}' not present in key set")

        self._default_kid = default_kid or self._select_default_kid()

        allowed = tuple(allowed_algorithms) if allowed_algorithms else tuple({key.alg for key in key_list})
        if not allowed:
            allowed = _DEFAULT_ALLOWED_ALGORITHMS
        for alg in allowed:
            if alg not in _DEFAULT_ALLOWED_ALGORITHMS:
                raise ServiceTokenError(f"unsupported algorithm '{alg}' in key set")
        self._allowed_algorithms = allowed

    def _select_default_kid(self) -> str:
        for key in self._keys.values():
            if key.private_key:
                return key.kid
        return next(iter(self._keys))

    @property
    def default_kid(self) -> str:
        return self._default_kid

    @property
    def allowed_algorithms(self) -> Sequence[str]:
        return self._allowed_algorithms

    def get(self, kid: str) -> ServiceKey:
        try:
            return self._keys[kid]
        except KeyError as exc:
            raise ServiceTokenValidationError(f"unknown key identifier '{kid}'") from exc

    def get_signing_key(self, kid: Optional[str] = None) -> ServiceKey:
        key_id = kid or self._default_kid
        key = self.get(key_id)
        # ensure it has private key
        key.ensure_signing_material()
        return key

    def keys(self) -> Sequence[ServiceKey]:
        return list(self._keys.values())

    def as_jwks(self) -> Mapping[str, Any]:
        jwks: list[Any] = []
        for key in self._keys.values():
            if isinstance(key.public_key, Mapping):
                jwks.append(dict(key.public_key))
        return {"keys": jwks}

    @classmethod
    def from_key_definitions(
        cls,
        definitions: Iterable[Mapping[str, Any]],
        *,
        default_kid: Optional[str] = None,
        allowed_algorithms: Optional[Sequence[str]] = None,
    ) -> "ServiceKeySet":
        keys: list[ServiceKey] = []
        for definition in definitions:
            kid = definition.get("kid")
            alg = definition.get("alg")
            if not kid or not alg:
                raise ServiceTokenError("each key definition must include 'kid' and 'alg'")
            private_key = definition.get("private_key")
            public_key = definition.get("public_key") or definition.get("public_jwk")
            use = definition.get("use", "sig")
            not_before = definition.get("nbf") or definition.get("not_before")
            expires_at = definition.get("exp") or definition.get("expires_at")
            keys.append(
                ServiceKey(
                    kid=str(kid),
                    alg=str(alg),
                    private_key=private_key,
                    public_key=public_key,
                    use=str(use),
                    not_before=int(not_before) if not_before is not None else None,
                    expires_at=int(expires_at) if expires_at is not None else None,
                )
            )
        return cls(keys, default_kid=default_kid, allowed_algorithms=allowed_algorithms)


@dataclass(slots=True)
class IssuedServiceToken:
    """Represents a freshly minted service JWT and its metadata."""

    token: str
    kid: str
    claims: Mapping[str, Any]
    headers: Mapping[str, Any]
    issued_at: int
    expires_at: int

    def as_bearer(self) -> str:
        return f"Bearer {self.token}"


class ReplayCache:
    """Deduplicate JWT identifiers using Redis with local fallback."""

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        *,
        namespace: str = "service_jwt",
        ttl_seconds: int = _DEFAULT_REPLAY_TTL_SECONDS,
        max_local_entries: int = _DEFAULT_LOCAL_CACHE_SIZE,
        metrics=security_metrics,
    ) -> None:
        self._redis = redis_client
        self._namespace = namespace
        self._ttl_seconds = max(1, int(ttl_seconds))
        self._max_local_entries = max(1, int(max_local_entries))
        self._metrics = metrics
        self._lock = threading.RLock()
        self._local: "OrderedDict[str, float]" = OrderedDict()

    def check_and_store(self, token_id: str, *, expires_at: Optional[int] = None) -> bool:
        """Return True if the identifier is new, False if it's a replay."""

        if not token_id:
            raise ServiceTokenValidationError("token identifier is required for replay detection")

        ttl = self._derive_ttl(expires_at)

        if self._redis is not None:
            namespaced_key = f"{self._namespace}:{token_id}"
            try:
                stored = self._redis.set(namespaced_key, "1", nx=True, ex=ttl)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Redis replay cache failure; using local fallback", exc_info=exc)
                if self._metrics:
                    self._metrics.incr(_METRIC_REPLAY_CACHE_REDIS_ERROR)
            else:
                if stored:
                    if self._metrics:
                        self._metrics.incr(_METRIC_REPLAY_CACHE_REDIS_STORE)
                    return True
                else:
                    if self._metrics:
                        self._metrics.incr(_METRIC_REPLAY_CACHE_REDIS_HIT)
                    return False

        return self._check_local(token_id, ttl)

    def _check_local(self, token_id: str, ttl: int) -> bool:
        now = time.time()
        expiry = now + ttl
        with self._lock:
            self._evict_expired(now)
            if token_id in self._local:
                if self._metrics:
                    self._metrics.incr(_METRIC_REPLAY_CACHE_LOCAL_HIT)
                return False
            self._local[token_id] = expiry
            self._local.move_to_end(token_id)
            if len(self._local) > self._max_local_entries:
                self._local.popitem(last=False)
                if self._metrics:
                    self._metrics.incr(_METRIC_REPLAY_CACHE_LOCAL_EVICT)
            if self._metrics:
                self._metrics.incr(_METRIC_REPLAY_CACHE_LOCAL_STORE)
            return True

    def _evict_expired(self, now: float) -> None:
        expired = [key for key, expiry in self._local.items() if expiry <= now]
        for key in expired:
            self._local.pop(key, None)

    def _derive_ttl(self, expires_at: Optional[int]) -> int:
        ttl = self._ttl_seconds
        if expires_at is not None:
            remaining = int(expires_at) - int(time.time())
            if remaining <= 0:
                # Already expired; we still insert with minimal TTL to prevent replays in the same tick.
                return 1
            ttl = min(ttl, remaining)
        return max(1, ttl)

    def clear(self) -> None:
        with self._lock:
            self._local.clear()


def issue_service_jwt(
    keyset: ServiceKeySet,
    *,
    subject: str,
    audience: str,
    issuer: str,
    ttl_seconds: int = _DEFAULT_TOKEN_TTL_SECONDS,
    scope: Optional[Sequence[str] | str] = None,
    nonce: Optional[str] = None,
    jti: Optional[str] = None,
    additional_claims: Optional[Mapping[str, Any]] = None,
    signing_kid: Optional[str] = None,
    not_before: Optional[int] = None,
) -> IssuedServiceToken:
    """Issue a short-lived service JWT using an asymmetric key."""

    if ttl_seconds <= 0 or ttl_seconds > _DEFAULT_TOKEN_TTL_SECONDS:
        raise ServiceTokenError(
            f"ttl_seconds must be between 1 and {_DEFAULT_TOKEN_TTL_SECONDS} (got {ttl_seconds})"
        )

    now = int(time.time())
    nbf = not_before if not_before is not None else now
    exp = now + int(ttl_seconds)
    token_id = jti or _random_identifier()
    token_nonce = nonce or _random_identifier()

    claims: MutableMapping[str, Any] = {
        "sub": subject,
        "aud": audience,
        "iss": issuer,
        "jti": token_id,
        "nonce": token_nonce,
        "iat": now,
        "nbf": nbf,
        "exp": exp,
    }

    if scope:
        if isinstance(scope, str):
            claims["scope"] = scope
        else:
            claims["scope"] = " ".join(scope)

    if additional_claims:
        for key, value in additional_claims.items():
            if key in claims:
                raise ServiceTokenError(f"claim '{key}' cannot be overridden")
            claims[key] = value

    signing_key = keyset.get_signing_key(signing_kid)
    headers = signing_key.header()

    token = jwt.encode(claims, signing_key.ensure_signing_material(), algorithm=signing_key.alg, headers=headers)

    return IssuedServiceToken(
        token=token,
        kid=signing_key.kid,
        claims=dict(claims),
        headers=dict(headers),
        issued_at=now,
        expires_at=exp,
    )


def verify_service_jwt(
    token: str,
    keyset: ServiceKeySet,
    *,
    audience: Optional[Sequence[str] | str] = None,
    issuer: Optional[str] = None,
    replay_cache: Optional[ReplayCache] = None,
    required_scope: Optional[Sequence[str]] = None,
    leeway_seconds: int = 5,
) -> Mapping[str, Any]:
    """Verify a service JWT and enforce replay protection if provided."""

    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise ServiceTokenValidationError("failed to parse token header") from exc

    kid = header.get("kid")
    if not kid:
        raise ServiceTokenValidationError("token missing 'kid' header")

    key = keyset.get(kid)
    algorithms = [key.alg]
    if key.alg not in keyset.allowed_algorithms:
        raise ServiceTokenValidationError(f"algorithm '{key.alg}' not allowed for kid='{kid}'")

    options = {
        "verify_aud": audience is not None,
        "verify_iss": issuer is not None,
    }

    try:
        claims = jwt.decode(
            token,
            key=key.verification_material(),
            algorithms=algorithms,
            audience=audience,
            issuer=issuer,
            options=options,
            leeway=leeway_seconds,
        )
    except ExpiredSignatureError as exc:
        raise ServiceTokenValidationError("token expired") from exc
    except JWTError as exc:
        raise ServiceTokenValidationError("token verification failed") from exc

    if required_scope:
        token_scope = claims.get("scope")
        if isinstance(token_scope, str):
            token_scopes = set(token_scope.split())
        elif isinstance(token_scope, Sequence):
            token_scopes = set(str(s) for s in token_scope)
        else:
            token_scopes = set()
        missing = [scope for scope in required_scope if scope not in token_scopes]
        if missing:
            raise ServiceTokenValidationError(f"token missing required scope(s): {', '.join(missing)}")

    if replay_cache is not None:
        replay_id = _build_replay_identifier(claims)
        expires_at = claims.get("exp")
        if not replay_cache.check_and_store(replay_id, expires_at=expires_at):
            raise ServiceTokenValidationError("token replay detected")

    return claims


def build_auth_headers(token: str | IssuedServiceToken, *, header: str = "Authorization") -> Mapping[str, str]:
    """Construct request headers for passing the service token."""

    value = token.token if isinstance(token, IssuedServiceToken) else token
    if header.lower() == "authorization":
        return {header: f"Bearer {value}"}
    return {header: value}


def load_service_keyset_from_env(prefix: str = "SERVICE_JWT") -> ServiceKeySet:
    """Load a service key set from environment variables."""

    keyset_env = os.getenv(f"{prefix}_KEYSET_JSON")
    jwks_env = os.getenv(f"{prefix}_JWKS_JSON")
    default_kid = os.getenv(f"{prefix}_ACTIVE_KID") or os.getenv(f"{prefix}_KID")
    allowed_algs_env = os.getenv(f"{prefix}_ALGORITHMS")
    allowed_algorithms = (
        tuple(alg.strip() for alg in allowed_algs_env.split(",") if alg.strip())
        if allowed_algs_env
        else None
    )

    definitions: list[Mapping[str, Any]] = []

    if keyset_env:
        try:
            parsed = json.loads(keyset_env)
        except json.JSONDecodeError as exc:
            raise ServiceTokenError(f"{prefix}_KEYSET_JSON must be valid JSON") from exc
        if isinstance(parsed, Mapping):
            definitions.extend(parsed.get("keys", []))
            default_kid = parsed.get("default_kid", default_kid)
        elif isinstance(parsed, list):
            definitions.extend(parsed)
        else:
            raise ServiceTokenError(f"{prefix}_KEYSET_JSON must be an object or list")

    if jwks_env:
        try:
            jwks = json.loads(jwks_env)
        except json.JSONDecodeError as exc:
            raise ServiceTokenError(f"{prefix}_JWKS_JSON must be valid JSON") from exc
        if isinstance(jwks, Mapping):
            for entry in jwks.get("keys", []):
                if isinstance(entry, Mapping):
                    definitions.append(entry)

    if not definitions:
        # Fallback to single-key env variables
        kid = default_kid or os.getenv(f"{prefix}_KID")
        if not kid:
            raise ServiceTokenError(
                f"{prefix}_KEYSET_JSON or {prefix}_KID must be configured for service JWT keys"
            )
        alg = os.getenv(f"{prefix}_ALGORITHM", "RS256")
        private_key = _load_secret(f"{prefix}_PRIVATE_KEY")
        public_key = _load_secret(f"{prefix}_PUBLIC_KEY")
        jwk_json = os.getenv(f"{prefix}_PUBLIC_JWK")
        jwk: Optional[Any] = None
        if jwk_json:
            try:
                jwk = json.loads(jwk_json)
            except json.JSONDecodeError:
                logger.warning("Invalid JSON in %s_PUBLIC_JWK; falling back to PEM", prefix)
        definitions.append(
            {
                "kid": kid,
                "alg": alg,
                "private_key": private_key,
                "public_key": jwk if jwk is not None else public_key,
            }
        )

    # Ensure we don't duplicate entries for the same kid: prefer definitions with private keys.
    merged: dict[str, dict[str, Any]] = {}
    for entry in definitions:
        kid = entry.get("kid")
        if not kid:
            continue
        existing = merged.get(kid)
        if existing is None or entry.get("private_key"):
            merged[kid] = dict(entry)
        elif not existing.get("public_key"):
            merged[kid] = dict(entry)

    return ServiceKeySet.from_key_definitions(merged.values(), default_kid=default_kid, allowed_algorithms=allowed_algorithms)


def load_replay_cache_from_env(
    prefix: str = "SERVICE_JWT",
    *,
    namespace: str = "service_jwt",
    default_ttl_seconds: int = _DEFAULT_REPLAY_TTL_SECONDS,
    default_max_entries: int = _DEFAULT_LOCAL_CACHE_SIZE,
) -> ReplayCache:
    """Instantiate a ReplayCache based on environment configuration."""

    redis_url = os.getenv(f"{prefix}_REPLAY_REDIS_URL") or os.getenv("SERVICE_JWT_REDIS_URL")
    ttl_env = os.getenv(f"{prefix}_REPLAY_TTL_SECONDS")
    max_entries_env = os.getenv(f"{prefix}_REPLAY_LOCAL_MAX")

    ttl_seconds = int(ttl_env) if ttl_env and ttl_env.isdigit() else default_ttl_seconds
    max_entries = int(max_entries_env) if max_entries_env and max_entries_env.isdigit() else default_max_entries

    redis_client = None
    if redis_url:
        try:
            import redis  # type: ignore

            redis_client = redis.Redis.from_url(redis_url)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to initialize Redis replay cache client", exc_info=exc)

    return ReplayCache(
        redis_client,
        namespace=namespace,
        ttl_seconds=ttl_seconds,
        max_local_entries=max_entries,
    )


def _build_replay_identifier(claims: Mapping[str, Any]) -> str:
    issuer = claims.get("iss", "?")
    subject = claims.get("sub", "?")
    jti = claims.get("jti")
    if not jti:
        raise ServiceTokenValidationError("token missing 'jti' claim for replay protection")
    nonce = claims.get("nonce")
    token_id = f"{issuer}:{subject}:{jti}"
    if nonce:
        token_id = f"{token_id}:{nonce}"
    return token_id


def _load_secret(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value:
        return _normalize_pem(value)
    file_path = os.getenv(f"{name}_FILE")
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                return _normalize_pem(handle.read())
        except FileNotFoundError as exc:
            raise ServiceTokenError(f"secret file not found for {name}") from exc
    return None


def _normalize_pem(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    # Support \n-delimited environment secrets
    return value.replace("\\n", "\n")


def _random_identifier(length: int = 32) -> str:
    return secrets.token_urlsafe(length // 2)

