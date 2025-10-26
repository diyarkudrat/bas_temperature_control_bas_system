"""Flask middleware for authentication."""

import logging
import os
import threading
import time
from functools import wraps
from typing import Dict, Tuple, Optional, Any, List
from flask import request, jsonify, g
from .exceptions import AuthError
from .tenant_middleware import TenantMiddleware
from http.versioning import get_version_from_path

logger = logging.getLogger(__name__)


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
        # Defaults are conservative and safe; will be overridden by ServerConfig if present.
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
            try:
                logger.info(f"Rate limit (shadow) would block: key={key} remaining={remaining:.2f}")
            except Exception:
                pass
            return True, remaining, key
        return allowed, remaining, key


_request_rate_limiter = _RequestRateLimiter()


def require_auth(required_role="operator", require_tenant=False, provider: Optional[Any] = None):
    """Decorator for protected endpoints with optional tenant enforcement."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            logger.debug(f"Checking authentication for endpoint: {request.endpoint}")
            # Non-invasive provider injection (Phase 0): allow caller to pass a provider
            # or defer to request.auth_provider set by server wiring.
            try:
                if provider is not None and not hasattr(request, 'auth_provider'):
                    setattr(request, 'auth_provider', provider)
            except Exception:
                pass
            # Fast-path rate limit by tenant + API version (if enabled)
            try:
                allowed, remaining, key = _request_rate_limiter.check()
                if not allowed:
                    tenant_id, version = key
                    return jsonify({
                        "error": "Too many requests",
                        "code": "RATE_LIMITED",
                        "tenant": tenant_id,
                        "version": version
                    }), 429
            except Exception:
                # Never block on limiter errors
                pass
            
            # Validate required_role parameter
            if required_role not in ['operator', 'admin', 'read-only']:
                logger.error(f"Invalid required_role: {required_role}")
                return jsonify({"error": "Invalid role configuration", "code": "CONFIG_ERROR"}), 500
            
            # Skip auth if disabled
            if not hasattr(request, 'auth_config') or not request.auth_config or not request.auth_config.auth_enabled:
                logger.debug("Authentication disabled, allowing access")
                return f(*args, **kwargs)
            
            # Shadow mode - log but don't block
            if request.auth_config.auth_mode == "shadow":
                logger.info(f"Shadow mode: logging access to {request.endpoint}")
                session_id = request.headers.get('X-Session-ID') or request.cookies.get('bas_session_id')
                session = getattr(request, 'session', None)
                if hasattr(request, 'audit_logger'):
                    request.audit_logger.log_session_access(session_id, request.endpoint)
                return f(*args, **kwargs)
            
            # Enforced mode - prefer JWT verification first if a provider and token are present
            logger.debug("Authentication enforced, checking JWT or session")
            authz_header = request.headers.get('Authorization', '') or ''
            token: Optional[str] = None
            if isinstance(authz_header, str):
                h = authz_header.strip()
                # Robust, case-insensitive parsing of Bearer tokens
                parts = h.split()
                if len(parts) == 2 and parts[0].lower() == 'bearer' and parts[1]:
                    token = parts[1].strip()

            provider_obj = getattr(request, 'auth_provider', None)
            metrics = getattr(request, 'auth_metrics', None)
            # Determine whether session fallback is allowed. If the flag is absent,
            # maintain backward compatibility by allowing fallback.
            try:
                if hasattr(request, 'auth_config') and hasattr(request.auth_config, 'allow_session_fallback'):
                    allow_fallback = bool(getattr(request.auth_config, 'allow_session_fallback'))
                else:
                    allow_fallback = True
            except Exception:
                allow_fallback = True

            # If no Bearer token is provided and fallback is explicitly disabled,
            # fail closed with 401 rather than attempting session auth.
            if not token and not allow_fallback:
                return jsonify({
                    "error": "Authorization required",
                    "message": "Bearer token required",
                    "code": "AUTH_REQUIRED"
                }), 401
            if token and provider_obj is not None:
                start_ms = time.time() * 1000.0
                _log_jwt_attempt(metrics)
                try:
                    claims = provider_obj.verify_token(token)
                    if not isinstance(claims, dict):
                        raise ValueError("invalid claims")
                    setattr(request, 'user_claims', claims)
                    user_id = str(claims.get('sub', '') or '').strip()
                    roles: List[str] = []
                    try:
                        if user_id:
                            roles = list(provider_obj.get_user_roles(user_id))
                    except Exception:
                        roles = []
                    # Fallback to roles embedded in claims if provider roles unavailable/empty
                    if not roles:
                        roles = _extract_roles_from_claims_local(claims)

                    if not _claims_has_permission(roles, required_role):
                        logger.warning(f"JWT insufficient permissions for {user_id} to access {request.endpoint} (requires {required_role})")
                        _log_jwt_failure(metrics)
                        return jsonify({
                            "error": "Insufficient permissions",
                            "message": f"JWT roles missing permission: {required_role}",
                            "code": "PERMISSION_DENIED"
                        }), 403

                    if require_tenant:
                        tenant_result = _enforce_tenant_isolation_jwt(request)
                        if tenant_result is not True:
                            return tenant_result

                    logger.debug(f"JWT authentication successful for {user_id} accessing {request.endpoint}")
                    _log_jwt_success(metrics, start_ms)
                    return f(*args, **kwargs)
                except ValueError as exc:
                    logger.warning(f"JWT verification failed for endpoint {request.endpoint}: {exc}")
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

            # Fallback or legacy: require valid session
            logger.debug("Authentication enforced, checking session")
            sess_start_ms = time.time() * 1000.0
            _log_session_attempt(metrics)
            session_id = request.headers.get('X-Session-ID') or request.cookies.get('bas_session_id')
            
            # Validate session ID format
            if not session_id or not isinstance(session_id, str) or len(session_id) < 10:
                logger.warning(f"Invalid session ID format for {request.endpoint}")
                _audit_auth_failure("INVALID_SESSION_ID", request.remote_addr, request.endpoint)
                _log_session_failure(metrics)
                return jsonify({
                    "error": "Invalid session ID",
                    "message": "Please login again",
                    "code": "INVALID_SESSION_ID"
                }), 401
            
            session_manager = getattr(request, 'session_manager', None)
            if not session_manager:
                logger.error("Session manager not available")
                return jsonify({"error": "Authentication system not available", "code": "AUTH_SYSTEM_ERROR"}), 500
            
            session = session_manager.validate_session(session_id, request)
            if not session:
                logger.warning(f"Invalid or expired session for {request.endpoint}")
                _audit_auth_failure("SESSION_INVALID", request.remote_addr, request.endpoint)
                _log_session_failure(metrics)
                return jsonify({
                    "error": "Invalid or expired session",
                    "message": "Please login again",
                    "code": "SESSION_INVALID"
                }), 401
            
            # Check role permissions
            if not _has_permission(session.role, required_role):
                logger.warning(f"Insufficient permissions for {session.username} ({session.role}) to access {request.endpoint} (requires {required_role})")
                _audit_permission_denied(session.username, session.user_id, request.remote_addr, request.endpoint, f"ROLE_{required_role.upper()}")
                return jsonify({
                    "error": "Insufficient permissions",
                    "message": f"{session.role} role cannot perform this action",
                    "code": "PERMISSION_DENIED"
                }), 403
            
            # Enforce tenant isolation if required
            if require_tenant:
                tenant_result = _enforce_tenant_isolation(session, request)
                if tenant_result is not True:
                    return tenant_result
            
            # Update last access
            session_manager.update_last_access(session_id)
            
            # Add session to request context
            request.session = session
            
            # Log access
            if hasattr(request, 'audit_logger'):
                request.audit_logger.log_session_access(session_id, request.endpoint)
            
            logger.debug(f"Authentication successful for {session.username} accessing {request.endpoint}")
            _log_session_success(metrics, sess_start_ms)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def _has_permission(user_role: str, required_role: str) -> bool:
    """Check if user role has permission for required role."""
    logger.debug(f"Checking permission: {user_role} -> {required_role}")
    
    role_hierarchy = {
        "read-only": 1,
        "operator": 2,
        "admin": 3
    }
    
    user_level = role_hierarchy.get(user_role, 0)
    required_level = role_hierarchy.get(required_role, 0)
    
    has_permission = user_level >= required_level
    logger.debug(f"Permission check result: {has_permission}")
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


def _claims_has_permission(user_roles: List[str], required_role: str) -> bool:
    """Check if any of the user's roles satisfies the required role using hierarchy."""
    normalized = set(r.lower() for r in user_roles)
    if required_role == 'read-only':
        return bool(normalized & {'read-only', 'operator', 'admin'})
    if required_role == 'operator':
        return bool(normalized & {'operator', 'admin'})
    if required_role == 'admin':
        return 'admin' in normalized
    return False

def _extract_roles_from_claims_local(claims: Dict[str, Any]) -> List[str]:
    """Extract roles from common claim keys with normalization and de-dupe.

    Accepts any of:
      - roles: [str]
      - permissions: [str]
      - any "*/roles": [str] (custom namespace)
    """
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

def _enforce_tenant_isolation(session, request):
    """Enforce tenant isolation for the session."""
    try:
        # Get tenant ID from request header
        tenant_header = getattr(request.auth_config, 'tenant_id_header', 'X-BAS-Tenant')
        requested_tenant_id = request.headers.get(tenant_header)
        
        if not requested_tenant_id:
            logger.warning(f"Missing tenant ID in request to {request.endpoint}")
            _audit_permission_denied(
                session.username, session.user_id, request.remote_addr, 
                request.endpoint, "MISSING_TENANT_ID"
            )
            return jsonify({
                'error': 'Tenant ID required',
                'code': 'MISSING_TENANT_ID'
            }), 400
        
        # Get user's tenant from session
        user_tenant_id = getattr(session, 'tenant_id', None)
        if not user_tenant_id:
            logger.warning(f"No tenant ID in session for user {session.username}")
            _audit_permission_denied(
                session.username, session.user_id, request.remote_addr,
                request.endpoint, "NO_SESSION_TENANT"
            )
            return jsonify({
                'error': 'User not assigned to tenant',
                'code': 'NO_SESSION_TENANT'
            }), 400
        
        # Validate tenant access
        if user_tenant_id != requested_tenant_id:
            logger.warning(f"Tenant violation: user {session.username} "
                         f"attempted to access tenant {requested_tenant_id}, "
                         f"allowed tenant: {user_tenant_id}")
            
            _audit_tenant_violation(
                session.user_id, session.username, request.remote_addr,
                requested_tenant_id, user_tenant_id
            )
            
            return jsonify({
                'error': 'Access denied to tenant',
                'code': 'TENANT_ACCESS_DENIED'
            }), 403
        
        # Store validated tenant ID in request context
        g.tenant_id = requested_tenant_id
        
        return True
        
    except Exception as e:
        logger.error(f"Error enforcing tenant isolation: {e}")
        return jsonify({
            'error': 'Tenant validation error',
            'code': 'TENANT_VALIDATION_ERROR'
        }), 500


def _enforce_tenant_isolation_jwt(request):
    """Enforce tenant isolation for JWT-authenticated requests using header only."""
    try:
        tenant_header = getattr(request.auth_config, 'tenant_id_header', 'X-BAS-Tenant') if hasattr(request, 'auth_config') else 'X-BAS-Tenant'
        requested_tenant_id = request.headers.get(tenant_header)
        if not requested_tenant_id:
            logger.warning(f"Missing tenant ID in JWT request to {request.endpoint}")
            return jsonify({
                'error': 'Tenant ID required',
                'code': 'MISSING_TENANT_ID'
            }), 400
        g.tenant_id = requested_tenant_id
        return True
    except Exception as e:
        logger.error(f"Error enforcing tenant isolation (JWT): {e}")
        return jsonify({
            'error': 'Tenant validation error',
            'code': 'TENANT_VALIDATION_ERROR'
        }), 500

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
        logger.error(f"Failed to audit auth failure: {e}")

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
        logger.error(f"Failed to audit permission denied: {e}")

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
        logger.error(f"Failed to audit tenant violation: {e}")

def add_security_headers(response):
    """Add security headers to response."""
    logger.debug("Adding security headers to response")
    
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    for header, value in security_headers.items():
        response.headers[header] = value
    
    logger.debug("Security headers added successfully")
    return response

def log_request_info():
    """Log request information for debugging."""
    logger.debug(f"Request: {request.method} {request.path}")
    logger.debug(f"IP: {request.remote_addr}")
    logger.debug(f"User-Agent: {request.headers.get('User-Agent', 'Unknown')}")
    logger.debug(f"Session-ID: {request.headers.get('X-Session-ID', 'None')}")

def handle_auth_error(error):
    """Handle authentication errors."""
    logger.error(f"Authentication error: {error}")
    
    if isinstance(error, AuthError):
        return jsonify({
            "error": "Authentication error",
            "message": str(error),
            "code": "AUTH_ERROR"
        }), 401
    else:
        return jsonify({
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "code": "INTERNAL_ERROR"
        }), 500
