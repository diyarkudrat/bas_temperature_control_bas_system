"""HTTP authentication and request security middleware (new home).

This module provides `require_auth` and helpers without importing legacy
`server.auth.middleware`. It integrates with:
- app_platform.rate_limit.sliding_window_limiter.RateLimiter for per-user limits
- adapters.cache.redis.revocation_service.RevocationService for revocations
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import defaultdict
from functools import wraps
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from flask import current_app, g, jsonify, request

from logging_lib import get_logger as get_structured_logger

from app_platform.rate_limit.sliding_window_limiter import RateLimiter as RedisSlidingLimiter
from adapters.cache.redis.revocation_service import RevocationService

try:
    # Prefer new location for version classification
    from apps.api.http.versioning import get_version_from_path
except Exception:  # pragma: no cover
    def get_version_from_path(_p: str) -> str:  # type: ignore
        return "0"


logger = get_structured_logger("api.http.middleware.auth")
rate_logger = get_structured_logger("api.http.middleware.auth.rate")
revocation_logger = get_structured_logger("api.http.middleware.auth.revocation")


def _scrub_identifier(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:12]


# Lightweight, non-blocking token-bucket limiter keyed by (tenant_id, api_version)
class _TokenBucket:
    def __init__(self, capacity: int, refill_rate_per_sec: float):
        self.capacity = capacity
        self.refill_rate_per_sec = refill_rate_per_sec
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def allow(self) -> Tuple[bool, float]:
        now = time.monotonic()
        with self.lock:
            elapsed = now - self.last_refill
            if elapsed > 0:
                self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate_per_sec)
                self.last_refill = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True, self.tokens
            return False, self.tokens


class _RequestRateLimiter:
    """Per-tenant, per-version request limiter.

    Disabled by default. Enable with env:
      BAS_REQ_RATE_LIMIT_ENABLED=1
      BAS_REQ_RATE_LIMIT_RPS=50
      BAS_REQ_RATE_LIMIT_BURST=100
    """

    def __init__(self):
        # Defaults are conservative and safe; can be overridden by ServerConfig if attached to request
        self.enabled = os.getenv('BAS_REQ_RATE_LIMIT_ENABLED', '0').lower() in {'1', 'true', 'yes'}
        self.shadow = os.getenv('BAS_REQ_RATE_LIMIT_SHADOW', '0').lower() in {'1', 'true', 'yes'}
        self.refill_rps = float(os.getenv('BAS_REQ_RATE_LIMIT_RPS', '50'))
        self.capacity = int(os.getenv('BAS_REQ_RATE_LIMIT_BURST', '100'))
        self._buckets: Dict[Tuple[str, str], _TokenBucket] = {}
        self._lock = threading.Lock()
        # Minimal metrics counters
        self._allowed_count = 0
        self._limited_count = 0

    def _key_from_request(self):
        try:
            tenant_header = getattr(request.auth_config, 'tenant_id_header', 'X-BAS-Tenant') if hasattr(request, 'auth_config') else 'X-BAS-Tenant'
            tenant_id = request.headers.get(tenant_header) or getattr(getattr(request, 'session', None), 'tenant_id', None) or 'public'
        except Exception:
            tenant_id = 'public'
        try:
            version = get_version_from_path(getattr(request, 'path', '') or '') or '0'
        except Exception:
            version = '0'
        return tenant_id, version

    def _sync_from_server_config_if_available(self):
        try:
            cfg = getattr(getattr(request, 'server_config', None), 'rate_limit', None)
            if cfg is None:
                return
            # Apply clamped values
            self.enabled = bool(getattr(cfg, 'enabled', self.enabled))
            self.shadow = bool(getattr(cfg, 'shadow_mode', self.shadow))
            self.refill_rps = float(getattr(cfg, 'requests_per_second', self.refill_rps))
            self.capacity = int(getattr(cfg, 'burst_capacity', self.capacity))
        except Exception:
            pass

    def check(self) -> Tuple[bool, float, Tuple[str, str]]:
        # Pull centralized configuration when available
        self._sync_from_server_config_if_available()

        if not self.enabled:
            return True, float('inf'), ('', '')

        key = self._key_from_request()

        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _TokenBucket(self.capacity, self.refill_rps)
                self._buckets[key] = bucket
        allowed, remaining = bucket.allow()
        with self._lock:
            if allowed:
                self._allowed_count += 1
            else:
                self._limited_count += 1
        # If shadow mode, never block
        if not allowed and self.shadow:
            rate_logger.info(
                "Rate limit shadow hit",
                extra={
                    "tenant": key[0],
                    "version": key[1],
                    "remaining": round(remaining, 2),
                },
            )
            return True, remaining, key
        if not allowed:
            rate_logger.warning(
                "Rate limit enforced",
                extra={
                    "tenant": key[0],
                    "version": key[1],
                    "remaining": round(remaining, 2),
                },
            )
        return allowed, remaining, key


_request_rate_limiter = _RequestRateLimiter()
_override_timeouts = defaultdict(float)
_override_lock = threading.Lock()


def parse_authorization_header(authz_header: Optional[str]) -> Optional[str]:
    """Extract Bearer token from Authorization header.

    Returns the token string if present, else None. Robust to whitespace and case.
    """
    try:
        if not isinstance(authz_header, str):
            return None
        parts = authz_header.strip().split()
        if len(parts) == 2 and parts[0].lower() == 'bearer' and parts[1]:
            return parts[1].strip()
    except Exception:
        pass
    return None


def classify_path(path: str) -> str:
    """Public helper that delegates to internal classifier; kept for clarity."""
    return path_classify(path)


def check_rate_limit() -> Optional[Tuple[Any, int]]:
    """Run request-level and per-user endpoint rate limits.

    Returns Flask (response, status) when limited, or None when allowed.
    Never raises and never blocks on limiter errors.
    """
    try:
        allowed, _remaining, key = _request_rate_limiter.check()
        if not allowed:
            tenant_id, version = key
            return jsonify({
                "error": "Too many requests",
                "code": "RATE_LIMITED",
                "tenant": tenant_id,
                "version": version
            }), 429
    except Exception:
        # ignore limiter failures
        pass

    # Per-user dynamic endpoint limiter via Redis sliding window (if configured)
    try:
        # Prefer hot-reloaded snapshot if available; fall back to static config
        cfg = getattr(request, 'rate_limit_snapshot', None)
        if cfg is None:
            cfg = getattr(getattr(request, 'server_config', None), 'rate_limit', None)
        per_user_limits = getattr(cfg, 'per_user_limits', {}) if cfg else {}
        if isinstance(per_user_limits, dict) and per_user_limits:
            # Identify user by unverified JWT sub (if present) else IP
            identity = request.remote_addr or 'anon'
            token_str = parse_authorization_header(request.headers.get('Authorization', '') or '') or ''
            try:
                if token_str:
                    from jose import jwt  # type: ignore[import]
                    claims = jwt.get_unverified_claims(token_str)
                    sub = str(claims.get('sub') or '').strip()
                    if sub:
                        identity = sub
            except Exception:
                pass
            # Connect Redis best-effort
            redis_client = None
            try:
                url = None
                server_cfg = getattr(request, 'server_config', None)
                if server_cfg and getattr(server_cfg, 'emulator_redis_url', None):
                    url = server_cfg.emulator_redis_url
                else:
                    url = os.getenv('RATE_LIMIT_REDIS_URL')
                if url:
                    import redis  # type: ignore
                    redis_client = redis.Redis.from_url(
                        url,
                        socket_timeout=1.0,
                        socket_connect_timeout=1.0,
                        retry_on_timeout=True,
                    )
            except Exception:
                redis_client = None
            if redis_client is not None:
                limiter = getattr(request, '_per_user_limiter', None)
                if limiter is None:
                    limiter = RedisSlidingLimiter(redis_client, key_prefix='auth:rl')
                    setattr(request, '_per_user_limiter', limiter)
                endpoint_key = getattr(getattr(request, 'url_rule', None), 'rule', None) or request.path
                ep_cfg = per_user_limits.get(endpoint_key) or per_user_limits.get('*')
                if isinstance(ep_cfg, dict):
                    window_s = int(ep_cfg.get('window_s', 60))
                    max_req = int(ep_cfg.get('max_req', 100))
                    ok, _ = limiter.check_limit(identity, endpoint_key, window_s, max_req, time.time())
                    if not ok:
                        retry_after = max(1, int(window_s / max(1, max_req)))
                        resp = jsonify({
                            "error": "Too many requests",
                            "code": "RATE_LIMITED",
                            "identity": identity,
                            "endpoint": endpoint_key
                        })
                        resp.headers['Retry-After'] = str(retry_after)
                        return resp, 429
    except Exception:
        pass
    return None


def enforce_revocation_check(token: str) -> Optional[Tuple[Any, int]]:
    """Check revocation using Redis-backed service with small local cache.

    Returns a Flask response when revoked; otherwise None.
    """
    try:
        # Best-effort Redis client from env (emulator or production wiring)
        service = getattr(request, '_revocation_service', None)
        cache = getattr(request, '_revocation_cache', None)
        if service is None:
            redis_client = None
            try:
                server_cfg = getattr(request, 'server_config', None)
                url = None
                if server_cfg and getattr(server_cfg, 'emulator_redis_url', None):
                    url = server_cfg.emulator_redis_url
                else:
                    url = os.getenv('REVOCATION_REDIS_URL')
                if url:
                    import redis  # type: ignore
                    redis_client = redis.Redis.from_url(
                        url,
                        socket_timeout=1.0,
                        socket_connect_timeout=1.0,
                        retry_on_timeout=True,
                    )
            except Exception:
                redis_client = None
            service = RevocationService(redis_client, ttl_s=float(os.getenv('REVOCATION_TTL_S', '3600')))
            setattr(request, '_revocation_service', service)
        if cache is None:
            from adapters.cache.redis.revocation_cache import LocalRevocationCache
            # Use small negative TTL to reduce Redis calls while bounding staleness
            cache = LocalRevocationCache(ttl_s=5.0, neg_ttl_s=1.0)
            setattr(request, '_revocation_cache', cache)

        # Extract token id (prefer jti)
        token_id = None
        try:
            from jose import jwt  # type: ignore[import]
            unverified = jwt.get_unverified_claims(token)
            token_id = str(unverified.get('jti') or '').strip() or None
        except Exception:
            token_id = None
        if token_id:
            token_hash = _scrub_identifier(token_id)
            try:
                # Fast-path: recently known revoked -> deny immediately
                if cache.is_recently_revoked(token_id):
                    revocation_logger.info(
                        "Token revoked via local cache",
                        extra={"token_hash": token_hash},
                    )
                    return jsonify({
                        "error": "Token revoked",
                        "code": "TOKEN_REVOKED"
                    }), 403
                # Negative cache: skip network call briefly if known not revoked
                if hasattr(cache, 'is_recently_not_revoked') and cache.is_recently_not_revoked(token_id):
                    return None
                # Check authoritative store
                if service.is_revoked(token_id):
                    # Remember locally to avoid duplicate checks briefly
                    cache.set_revoked(token_id)
                    revocation_logger.warning(
                        "Token revoked via upstream store",
                        extra={"token_hash": token_hash},
                    )
                    return jsonify({
                        "error": "Token revoked",
                        "code": "TOKEN_REVOKED"
                    }), 403
                # Cache negative result with short TTL
                if hasattr(cache, 'set_not_revoked'):
                    cache.set_not_revoked(token_id)
            except Exception:
                # Fail-closed only on positive cache hits; otherwise ignore errors
                pass
    except Exception:
        pass
    return None


def verify_and_decode_jwt(provider_obj: Any, token: str, metrics: Optional[Any]) -> Dict[str, Any]:
    """Verify JWT with provider, record metrics, and return claims dict.

    Raises ValueError on verification failure.
    """
    start_ms = time.time() * 1000.0
    _log_jwt_attempt(metrics)
    claims = provider_obj.verify_token(token)
    if not isinstance(claims, dict):
        raise ValueError("invalid claims")
    setattr(request, 'user_claims', claims)
    _log_jwt_success(metrics, start_ms)
    return claims


def authorize_roles(claims: Dict[str, Any], provider_obj: Any, required_role: str) -> Tuple[bool, Optional[Tuple[Any, int]]]:
    """Authorize according to path sensitivity using claims-only or provider metadata.

    Returns (True, None) on success; (False, (response, status)) when denied/unavailable.
    """
    classify = classify_path(request.path)
    if classify != 'critical':
        if claims_only_check(claims, required_role):
            return True, None
        return False, (jsonify({
            "error": "Insufficient permissions",
            "message": f"JWT roles missing permission: {required_role}",
            "code": "PERMISSION_DENIED"
        }), 403)

    # critical: require provider metadata, allow admin outage override on failure
    user_id = str(claims.get('sub', '') or '').strip()
    try:
        success = full_metadata_check(user_id, provider_obj, required_role)
        if not success:
            return False, (jsonify({
                "error": "Insufficient permissions",
                "message": f"JWT roles missing permission: {required_role}",
                "code": "PERMISSION_DENIED"
            }), 403)
        return True, None
    except Exception as exc:
        if admin_outage_override(user_id, claims):
            if claims_only_check(claims, required_role):
                return True, None
            return False, (jsonify({
                "error": "Insufficient permissions",
                "message": f"JWT roles missing permission: {required_role}",
                "code": "PERMISSION_DENIED"
            }), 403)
        logger.warning(
            "Full metadata check failed",
            extra={"endpoint": request.endpoint, "error": str(exc)},
        )
        return False, (jsonify({
            "error": "Authorization service unavailable",
            "code": "AUTH_UNAVAILABLE"
        }), 503)


def write_auth_audit(kind: str, **kwargs: Any) -> None:
    """Unified audit writer wrapper around existing sinks.

    kind in {"AUTH_FAILURE", "PERMISSION_DENIED", "TENANT_VIOLATION"}.
    Remaining kwargs forwarded to specific audit helpers.
    """
    try:
        if kind == "AUTH_FAILURE":
            _audit_auth_failure(
                kwargs.get('reason', ''),
                kwargs.get('ip_address', request.remote_addr),
                kwargs.get('endpoint', request.endpoint),
            )
        elif kind == "PERMISSION_DENIED":
            _audit_permission_denied(
                kwargs.get('username', ''),
                kwargs.get('user_id', ''),
                kwargs.get('ip_address', request.remote_addr),
                kwargs.get('endpoint', request.endpoint),
                kwargs.get('reason', ''),
            )
        elif kind == "TENANT_VIOLATION":
            _audit_tenant_violation(
                kwargs.get('user_id', ''),
                kwargs.get('username', ''),
                kwargs.get('ip_address', request.remote_addr),
                kwargs.get('attempted_tenant', ''),
                kwargs.get('allowed_tenant', ''),
            )
    except Exception:
        # Never fail open/closed based on audit failures
        pass


def require_auth(required_role="operator", require_tenant=False, provider: Optional[Any] = None):
    """Decorator for protected endpoints with optional tenant enforcement."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                logger.debug(
                    "Checking authentication",
                    extra={"endpoint": request.endpoint},
                )
                try:
                    if provider is not None and not hasattr(request, 'auth_provider'):
                        setattr(request, 'auth_provider', provider)
                except Exception:
                    pass

                limited = check_rate_limit()
                if limited is not None:
                    return limited

                if required_role not in ['operator', 'admin', 'read-only']:
                    logger.error(
                        "Invalid required role",
                        extra={"required_role": required_role, "endpoint": request.endpoint},
                    )
                    return jsonify({"error": "Invalid role configuration", "code": "CONFIG_ERROR"}), 500

                if not hasattr(request, 'auth_config') or not request.auth_config or not request.auth_config.auth_enabled:
                    logger.debug(
                        "Authentication disabled, allowing access",
                        extra={"endpoint": request.endpoint},
                    )
                    return f(*args, **kwargs)

                if request.auth_config.auth_mode == "shadow":
                    logger.info(
                        "Shadow mode access",
                        extra={"endpoint": request.endpoint},
                    )
                    session_id = request.headers.get('X-Session-ID') or request.cookies.get('bas_session_id')
                    if hasattr(request, 'audit_logger'):
                        request.audit_logger.log_session_access(session_id, request.endpoint)
                    return f(*args, **kwargs)

                logger.debug(
                    "Authentication enforced",
                    extra={"endpoint": request.endpoint},
                )
                token: Optional[str] = parse_authorization_header(request.headers.get('Authorization', '') or '')
                provider_obj = getattr(request, 'auth_provider', None)
                metrics = getattr(request, 'auth_metrics', None)

                try:
                    if hasattr(request, 'auth_config') and hasattr(request.auth_config, 'allow_session_fallback'):
                        allow_fallback = bool(getattr(request.auth_config, 'allow_session_fallback'))
                    else:
                        allow_fallback = True
                except Exception:
                    allow_fallback = True

                if not token and not allow_fallback:
                    return jsonify({
                        "error": "Authorization required",
                        "message": "Bearer token required",
                        "code": "AUTH_REQUIRED"
                    }), 401

                if token and provider_obj is not None:
                    revoked = enforce_revocation_check(token)
                    if revoked is not None:
                        return revoked
                    try:
                        claims = verify_and_decode_jwt(provider_obj, token, metrics)
                        allowed, denial = authorize_roles(claims, provider_obj, required_role)
                        if not allowed:
                            _log_jwt_failure(metrics)
                            return denial  # type: ignore[return-value]
                        if require_tenant:
                            tenant_result = _ensure_tenant_header()
                            if tenant_result is not True:
                                return tenant_result
                        user_id = str(claims.get('sub', '') or '').strip()
                        logger.debug(
                            "JWT authentication successful",
                            extra={
                                "endpoint": request.endpoint,
                                "user_hash": _scrub_identifier(user_id),
                            },
                        )
                        return f(*args, **kwargs)
                    except ValueError as exc:
                        logger.warning(
                            "JWT verification failed",
                            extra={"endpoint": request.endpoint, "error": str(exc)},
                        )
                        _log_jwt_failure(metrics)
                        if not allow_fallback:
                            msg = str(exc).lower()
                            code = 'INVALID_TOKEN'
                            if 'exp' in msg or 'expired' in msg:
                                code = 'TOKEN_EXPIRED'
                            if 'claim' in msg:
                                code = 'INVALID_CLAIMS'
                            return jsonify({
                                "error": "Invalid or expired token",
                                "message": "JWT verification failed",
                                "code": code
                            }), 401
                        # else fall through to session checks

                logger.debug(
                    "Checking session fallback",
                    extra={"endpoint": request.endpoint},
                )
                sess_start_ms = time.time() * 1000.0
                _log_session_attempt(metrics)
                session_id = request.headers.get('X-Session-ID') or request.cookies.get('bas_session_id')

                if not session_id or not isinstance(session_id, str) or len(session_id) < 10:
                    logger.warning(
                        "Invalid session identifier",
                        extra={"endpoint": request.endpoint},
                    )
                    _audit_auth_failure("INVALID_SESSION_ID", request.remote_addr, request.endpoint)
                    _log_session_failure(metrics)
                    return jsonify({
                        "error": "Invalid session ID",
                        "message": "Please login again",
                        "code": "INVALID_SESSION_ID"
                    }), 401

                client = getattr(request, 'auth_service_client', None)
                if client is None:
                    logger.error(
                        "Auth service client unavailable",
                        extra={"endpoint": request.endpoint},
                    )
                    return jsonify({"error": "Authentication service unavailable", "code": "AUTH_SERVICE_ERROR"}), 503

                try:
                    upstream = client.status(
                        session_id=session_id,
                        cookies=dict(request.cookies) if request.cookies else None,
                    )
                except ConnectionError:
                    logger.error(
                        "Auth service status request failed",
                        extra={"endpoint": request.endpoint},
                        exc_info=True,
                    )
                    return jsonify({"error": "Auth service unreachable", "code": "AUTH_UPSTREAM_UNAVAILABLE"}), 502

                if not upstream.ok:
                    payload = upstream.json or {
                        "error": "Invalid or expired session",
                        "code": "SESSION_INVALID",
                    }
                    _audit_auth_failure(payload.get("code", "SESSION_INVALID"), request.remote_addr, request.endpoint)
                    _log_session_failure(metrics)
                    resp = jsonify(payload)
                    for cookie_header in upstream.set_cookies:
                        resp.headers.add("Set-Cookie", cookie_header)
                    return resp, upstream.status_code or 502

                payload = upstream.json or {}
                user_payload = payload.get("user", {}) if isinstance(payload, dict) else {}
                username = str(user_payload.get("username") or "")
                role = str(user_payload.get("role") or "")
                user_id = user_payload.get("user_id", "unknown")
                tenant_id = user_payload.get("tenant_id")

                if not username:
                    logger.warning(
                        "Auth service status response missing username",
                        extra={"endpoint": request.endpoint},
                    )
                    _log_session_failure(metrics)
                    return jsonify({
                        "error": "Invalid session response",
                        "code": "SESSION_INVALID",
                    }), 502

                if not _has_permission(role, required_role):
                    logger.warning(
                        "Insufficient permissions",
                        extra={
                            "endpoint": request.endpoint,
                            "user_hash": _scrub_identifier(username),
                            "role": role,
                            "required_role": required_role,
                        },
                    )
                    _audit_permission_denied(username, user_id, request.remote_addr, request.endpoint, f"ROLE_{required_role.upper()}")
                    return jsonify({
                        "error": "Insufficient permissions",
                        "message": f"{role} role cannot perform this action",
                        "code": "PERMISSION_DENIED"
                    }), 403

                session_obj = SimpleNamespace(
                    session_id=session_id,
                    username=username,
                    role=role,
                    user_id=user_id,
                    tenant_id=tenant_id,
                    created_at=user_payload.get("login_time"),
                )

                if require_tenant:
                    tenant_result = _ensure_tenant_isolation(session_obj)
                    if tenant_result is not True:
                        return tenant_result

                request.session = session_obj
                logger.debug(
                    "Session authentication successful",
                    extra={
                        "endpoint": request.endpoint,
                        "user_hash": _scrub_identifier(username),
                        "role": role,
                    },
                )
                _log_session_success(metrics, sess_start_ms)
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(
                    "Auth middleware error",
                    extra={"endpoint": request.endpoint, "error": str(e)},
                )
                return jsonify({"error": "Internal server error", "code": "INTERNAL_ERROR"}), 500
        return decorated_function
    return decorator


def _has_permission(user_role: str, required_role: str) -> bool:
    """Check if user role has permission for required role."""
    logger.debug(
        "Checking permission",
        extra={"user_role": user_role, "required_role": required_role},
    )

    role_hierarchy = {
        "read-only": 1,
        "operator": 2,
        "admin": 3
    }

    user_level = role_hierarchy.get(user_role, 0)
    required_level = role_hierarchy.get(required_role, 0)

    has_permission = user_level >= required_level
    logger.debug(
        "Permission check result",
        extra={"has_permission": has_permission, "user_role": user_role, "required_role": required_role},
    )
    return has_permission


def _log_jwt_attempt(metrics: Optional[Any]) -> None:
    try:
        if metrics is not None:
            metrics.inc_jwt_attempt()
    except Exception:
        pass


def _log_jwt_failure(metrics: Optional[Any]) -> None:
    try:
        if metrics is not None:
            metrics.inc_jwt_failure()
    except Exception:
        pass


def _log_jwt_success(metrics: Optional[Any], start_ms: float) -> None:
    try:
        if metrics is not None:
            metrics.observe_jwt_success(time.time() * 1000.0 - start_ms)
    except Exception:
        pass


def _log_session_attempt(metrics: Optional[Any]) -> None:
    try:
        if metrics is not None:
            metrics.inc_session_attempt()
    except Exception:
        pass


def _log_session_failure(metrics: Optional[Any]) -> None:
    try:
        if metrics is not None:
            metrics.inc_session_failure()
    except Exception:
        pass


def _log_session_success(metrics: Optional[Any], start_ms: float) -> None:
    try:
        if metrics is not None:
            metrics.observe_session_success(time.time() * 1000.0 - start_ms)
    except Exception:
        pass


def _extract_roles_from_claims_local(claims: Dict[str, Any]) -> List[str]:
    """Extract roles from common claim keys with normalization and de-dupe."""
    roles: List[str] = []
    try:
        if not isinstance(claims, dict):
            return []
        direct = claims.get('roles')
        if isinstance(direct, list):
            roles.extend([str(x) for x in direct])
        perms = claims.get('permissions')
        if isinstance(perms, list):
            roles.extend([str(x) for x in perms])
        for k, v in claims.items():
            if isinstance(k, str) and k.endswith('/roles') and isinstance(v, list):
                roles.extend([str(x) for x in v])
        # normalize and de-dupe
        seen = set()
        result: List[str] = []
        for r in roles:
            rl = r.strip()
            if rl and rl not in seen:
                seen.add(rl)
                result.append(rl)
        return result
    except Exception:
        return []


def _tenant_middleware_missing_response() -> Tuple[Any, int]:
    logger.warning("Tenant middleware not configured")
    return jsonify({
        "error": "Tenant middleware not configured",
        "code": "TENANT_MIDDLEWARE_MISSING",
    }), 500


def _ensure_tenant_header() -> Any:
    middleware = getattr(current_app, "tenant_middleware", None)
    if middleware is None:
        return _tenant_middleware_missing_response()

    result = middleware.require_tenant(lambda: True)()
    return result


def _ensure_tenant_isolation(session_obj: Any) -> Any:
    middleware = getattr(current_app, "tenant_middleware", None)
    if middleware is None:
        return _tenant_middleware_missing_response()

    original_session = getattr(request, "session", None)
    request.session = session_obj
    result = middleware.enforce_tenant_isolation(lambda: True)()

    if result is True:
        return True

    if original_session is not None:
        request.session = original_session
    else:
        try:
            delattr(request, "session")
        except Exception:
            request.session = None
    return result


def _audit_auth_failure(reason: str, ip_address: str, endpoint: str):
    """Audit authentication failure."""
    try:
        if hasattr(request, 'audit_logger') and request.audit_logger:
            # Try Firestore audit if available
            if hasattr(request.audit_logger, 'firestore_audit') and request.audit_logger.firestore_audit:
                request.audit_logger.firestore_audit.log_event(
                    event_type='AUTH_FAILURE',
                    ip_address=ip_address,
                    user_agent=request.headers.get('User-Agent'),
                    details={'endpoint': endpoint, 'reason': reason},
                    tenant_id=(getattr(request, 'tenant_id', None) or getattr(g, 'tenant_id', None))
                )
            else:
                # Fallback to SQLite audit
                request.audit_logger.log_auth_failure(None, ip_address, reason)
    except Exception as e:
        logger.error("Failed to audit auth failure", extra={"error": str(e)})


def _audit_permission_denied(username: str, user_id: str, ip_address: str, endpoint: str, reason: str):
    """Audit permission denied event."""
    try:
        if hasattr(request, 'audit_logger') and request.audit_logger:
            # Try Firestore audit if available
            if hasattr(request.audit_logger, 'firestore_audit') and request.audit_logger.firestore_audit:
                request.audit_logger.firestore_audit.log_event(
                    event_type='PERMISSION_DENIED',
                    user_id=user_id,
                    username=username,
                    ip_address=ip_address,
                    user_agent=request.headers.get('User-Agent'),
                    details={'endpoint': endpoint, 'reason': reason},
                    tenant_id=(getattr(request, 'tenant_id', None) or getattr(g, 'tenant_id', None))
                )
            else:
                # Fallback to SQLite audit
                request.audit_logger.log_permission_denied(username, user_id, ip_address, endpoint, reason)
    except Exception as e:
        logger.error("Failed to audit permission denied", extra={"error": str(e)})


def _audit_tenant_violation(user_id: str, username: str, ip_address: str, attempted_tenant: str, allowed_tenant: str):
    """Audit tenant access violation."""
    try:
        if hasattr(request, 'audit_logger') and request.audit_logger:
            # Try Firestore audit if available
            if hasattr(request.audit_logger, 'firestore_audit') and request.audit_logger.firestore_audit:
                request.audit_logger.firestore_audit.log_event(
                    event_type='TENANT_VIOLATION',
                    user_id=user_id,
                    username=username,
                    ip_address=ip_address,
                    user_agent=request.headers.get('User-Agent'),
                    details={
                        'attempted_tenant': attempted_tenant,
                        'allowed_tenant': allowed_tenant,
                        'endpoint': request.endpoint
                    },
                    tenant_id=attempted_tenant
                )
            else:
                # Fallback to SQLite audit
                request.audit_logger.log_tenant_violation(user_id, username, ip_address, attempted_tenant, allowed_tenant)
    except Exception as e:
        logger.error("Failed to audit tenant violation", extra={"error": str(e)})


def path_classify(path: str) -> str:
    rules = getattr(request.server_config, 'PATH_SENSITIVITY_RULES', [])
    for pattern, level in rules:
        try:
            import re
            if re.match(pattern, path):
                return level
        except Exception:
            continue
    return 'critical'  # fail-closed to full check


def claims_only_check(claims: Dict[str, Any], required_role: str) -> bool:
    roles = _extract_roles_from_claims_local(claims)
    return _claims_has_permission(roles, required_role)


def full_metadata_check(user_id: str, provider: Any, required_role: str) -> bool:
    roles = provider.get_user_roles(user_id)
    return _claims_has_permission(roles, required_role)


def admin_outage_override(user_id: str, claims: Dict[str, Any]) -> bool:
    roles = _extract_roles_from_claims_local(claims)
    if 'admin' not in [r.lower() for r in roles]:
        return False
    with _override_lock:
        now = time.time()
        if now - _override_timeouts[user_id] < 300:
            pass
        else:
            _override_timeouts[user_id] = now
    audit_logger = getattr(request, 'audit_logger', None)
    if audit_logger:
        audit_logger.log_event(
            event_type='ADMIN_OUTAGE_OVERRIDE',
            user_id=user_id,
            details={'reason': 'metadata outage', 'timestamp': time.time()}
        )
    return True


def _claims_has_permission(user_roles: List[str], required_role: str) -> bool:
    """Check if any of the user's roles satisfies the required role using hierarchy."""
    normalized = set(r.lower() for r in user_roles)
    if required_role == 'read-only':
        # Accept coarse roles OR granular read permissions for read-only endpoints
        if normalized & {'read-only', 'operator', 'admin'}:
            return True
        # Map common granular read permissions to read-only access
        for perm in normalized:
            # Generic patterns: read:* or *:read
            if perm.startswith('read:') or perm.endswith(':read'):
                return True
        # Known explicit read permissions used by this API
        if normalized & {'read:status', 'telemetry:read', 'config:read'}:
            return True
        return False
    if required_role == 'operator':
        return bool(normalized & {'operator', 'admin'})
    if required_role == 'admin':
        return 'admin' in normalized
    return False


__all__ = [
    "require_auth",
]


