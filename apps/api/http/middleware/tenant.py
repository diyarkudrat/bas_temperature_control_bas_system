"""Tenant middleware.

Implements tenant context setup and decorators.
"""

from __future__ import annotations

import logging
import time
import threading
from typing import Optional, Dict, Any, Callable
from types import SimpleNamespace
from functools import wraps

from flask import current_app, g as flask_g, has_request_context
from flask import jsonify as _flask_jsonify
from flask import request as _flask_request

from app_platform.config.auth import AuthConfig


logger = logging.getLogger(__name__)

# Module-level globals for tests to patch without Flask context
g = SimpleNamespace()
request = None  # will be patched in tests; fallback to _flask_request at runtime
jsonify = _flask_jsonify


def get_request():
    """Return patched request if provided, else real Flask request proxy."""
    return request if request is not None else _flask_request


class TenantMiddleware:
    """Middleware for enforcing multi-tenant isolation."""

    def __init__(self, auth_config: AuthConfig, audit_service=None):
        self.auth_config = auth_config
        self.audit_service = audit_service
        self.tenant_header = auth_config.tenant_id_header
        # Small in-process TTL cache mapping principal/session -> tenant_id
        self._cache_ttl_s: int = 120
        self._cache_capacity: int = 1024
        self._principal_tenant_cache: Dict[str, tuple[str, float]] = {}
        self._cache_lock = threading.RLock()

    def _cache_get(self, principal: Optional[str]) -> Optional[str]:
        if not principal:
            return None
        now = time.monotonic()
        with self._cache_lock:
            entry = self._principal_tenant_cache.get(principal)
            if not entry:
                return None
            tenant_id, expires_at = entry
            if expires_at < now:
                try:
                    del self._principal_tenant_cache[principal]
                except Exception:
                    pass
                return None
            return tenant_id

    def _cache_set(self, principal: Optional[str], tenant_id: Optional[str]) -> None:
        if not principal or not tenant_id:
            return
        expires_at = time.monotonic() + max(1, float(self._cache_ttl_s))
        with self._cache_lock:
            if len(self._principal_tenant_cache) >= self._cache_capacity:
                now = time.monotonic()
                expired = [k for k, (_, exp) in self._principal_tenant_cache.items() if exp < now]
                for k in expired[: max(1, len(expired))]:
                    try:
                        del self._principal_tenant_cache[k]
                    except Exception:
                        pass
                if len(self._principal_tenant_cache) >= self._cache_capacity:
                    try:
                        first_key = next(iter(self._principal_tenant_cache))
                        del self._principal_tenant_cache[first_key]
                    except Exception:
                        pass
            self._principal_tenant_cache[principal] = (tenant_id, expires_at)

    def setup_tenant_context(self, req=None):
        """Resolve tenant_id once per request and cache it on request and Flask g.

        Resolution order:
          1) request.session.tenant_id (authoritative)
          2) trusted header (auth_config.tenant_id_header) when no session is present

        If a header is present and mismatches the session tenant, the session value
        wins and a warning is logged (optionally audited). Returns the resolved
        tenant_id or None.
        """
        try:
            request_obj = req or get_request()
        except Exception:
            request_obj = None

        if request_obj is None:
            return None

        # Reuse if already resolved earlier in the request lifecycle
        try:
            cached_tenant_id = getattr(request_obj, 'tenant_id', None)
            if cached_tenant_id is not None:
                # Ensure g also has the value for downstream code that reads g
                if has_request_context():
                    try:
                        setattr(flask_g, 'tenant_id', cached_tenant_id)
                    except Exception:
                        pass
                return cached_tenant_id
        except Exception:
            pass

        tenant_id = None
        header_tenant_id = None
        session_tenant_id = None

        # Principal identifier for cache (session header or cookie)
        try:
            principal_id = request_obj.headers.get('X-Session-ID') or request_obj.cookies.get('bas_session_id')
        except Exception:
            principal_id = None

        # Cache fast-path
        cached_tid = self._cache_get(principal_id)
        if cached_tid is not None:
            tenant_id = cached_tid
            try:
                setattr(request_obj, 'tenant_id', tenant_id)
            except Exception:
                pass
            if has_request_context():
                try:
                    setattr(flask_g, 'tenant_id', tenant_id)
                except Exception:
                    pass
            return tenant_id

        try:
            header_tenant_id = request_obj.headers.get(self.tenant_header)
        except Exception:
            header_tenant_id = None

        try:
            session_obj = getattr(request_obj, 'session', None)
            session_tenant_id = getattr(session_obj, 'tenant_id', None) if session_obj else None
        except Exception:
            session_tenant_id = None

        if session_tenant_id:
            tenant_id = session_tenant_id
            # Populate cache for principal
            self._cache_set(principal_id, session_tenant_id)
            if header_tenant_id and header_tenant_id != session_tenant_id:
                try:
                    logger.warning(
                        "Tenant header mismatch; using session tenant. header=%s session=%s endpoint=%s",
                        header_tenant_id,
                        session_tenant_id,
                        getattr(request_obj, 'endpoint', 'unknown')
                    )
                except Exception:
                    pass
                # Optional audit hook
                if self.audit_service:
                    try:
                        self.audit_service.log_tenant_violation(
                            user_id=getattr(session_obj, 'user_id', None),
                            username=getattr(session_obj, 'username', None),
                            ip_address=getattr(request_obj, 'remote_addr', ''),
                            attempted_tenant=header_tenant_id,
                            allowed_tenant=session_tenant_id
                        )
                    except Exception:
                        pass
        elif header_tenant_id:
            tenant_id = header_tenant_id
        else:
            tenant_id = None

        # Cache on request for downstream access and set Flask g
        try:
            setattr(request_obj, 'tenant_id', tenant_id)
        except Exception:
            pass
        if has_request_context() and tenant_id is not None:
            try:
                setattr(flask_g, 'tenant_id', tenant_id)
            except Exception:
                pass

        return tenant_id

    def extract_tenant_id(self, request) -> Optional[str]:
        """Extract tenant ID using cached value or from session/header."""
        # Prefer cached value
        try:
            cached = getattr(request, 'tenant_id', None)
            if cached is not None:
                return cached
        except Exception:
            pass

        # Prefer session value (authoritative)
        if hasattr(request, 'session') and request.session:
            session_tid = getattr(request.session, 'tenant_id', None)
            if session_tid:
                return session_tid

        # Fallback to header
        try:
            header_tid = request.headers.get(self.tenant_header)
            if header_tid:
                return header_tid
        except Exception:
            pass

        return None

    def validate_tenant_access(self, user_tenant_id: str, requested_tenant_id: str) -> bool:
        return user_tenant_id == requested_tenant_id

    def audit_tenant_violation(self, user_id: Optional[str], username: Optional[str],
                              ip_address: str, attempted_tenant: str, allowed_tenant: str):
        if self.audit_service:
            try:
                self.audit_service.log_tenant_violation(
                    user_id=user_id,
                    username=username,
                    ip_address=ip_address,
                    attempted_tenant=attempted_tenant,
                    allowed_tenant=allowed_tenant
                )
            except Exception as e:
                logger.error(f"Failed to audit tenant violation: {e}")

    def require_tenant(self, func: Callable) -> Callable:
        @wraps(func)
        def decorated_function(*args, **kwargs):
            req = get_request()
            tenant_id = self.extract_tenant_id(req)
            if not tenant_id:
                logger.warning(f"Missing tenant ID in request to {request.endpoint}")
                if self.audit_service:
                    session_obj = getattr(req, 'session', None)
                    username = getattr(session_obj, 'username', None)
                    user_id = getattr(session_obj, 'user_id', None)
                    self.audit_service.log_permission_denied(
                        username=username,
                        user_id=user_id,
                        ip_address=req.remote_addr,
                        resource=req.endpoint,
                        reason="MISSING_TENANT_ID"
                    )
                resp = jsonify({'error': 'Tenant ID required', 'code': 'MISSING_TENANT_ID'})
                return resp if isinstance(resp, tuple) else (resp, 400)

            if has_request_context():
                flask_g.tenant_id = tenant_id

            return func(*args, **kwargs)

        return decorated_function

    def enforce_tenant_isolation(self, func: Callable) -> Callable:
        @wraps(func)
        def decorated_function(*args, **kwargs):
            req = get_request()
            requested_tenant_id = self.extract_tenant_id(req)
            if not requested_tenant_id:
                logger.warning(f"Missing tenant ID in request to {req.endpoint}")
                resp = jsonify({'error': 'Tenant ID required', 'code': 'MISSING_TENANT_ID'})
                return resp if isinstance(resp, tuple) else (resp, 400)

            user_tenant_id = None
            if hasattr(req, 'session') and req.session:
                user_tenant_id = getattr(req.session, 'tenant_id', None)

            if not user_tenant_id:
                logger.warning(f"No user session for tenant-isolated endpoint {request.endpoint}")
                if has_request_context():
                    flask_g.tenant_id = requested_tenant_id
                return func(*args, **kwargs)

            if not self.validate_tenant_access(user_tenant_id, requested_tenant_id):
                logger.warning(f"Tenant violation: user {getattr(req.session, 'username', None)} "
                             f"attempted to access tenant {requested_tenant_id}, "
                             f"allowed tenant: {user_tenant_id}")

                self.audit_tenant_violation(
                    user_id=getattr(req.session, 'user_id', None),
                    username=getattr(req.session, 'username', None),
                    ip_address=req.remote_addr,
                    attempted_tenant=requested_tenant_id,
                    allowed_tenant=user_tenant_id
                )

                resp = jsonify({'error': 'Access denied to tenant', 'code': 'TENANT_ACCESS_DENIED'})
                return resp if isinstance(resp, tuple) else (resp, 403)

            if has_request_context():
                flask_g.tenant_id = requested_tenant_id

            return func(*args, **kwargs)

        return decorated_function

    def require_device_access(self, func: Callable) -> Callable:
        @wraps(func)
        def decorated_function(*args, **kwargs):
            try:
                tenant_id = getattr(flask_g, 'tenant_id', None)
            except Exception:
                tenant_id = None
            if not tenant_id:
                resp = jsonify({'error': 'Tenant ID not available', 'code': 'TENANT_ID_MISSING'})
                return resp if isinstance(resp, tuple) else (resp, 400)

            req = get_request()
            device_id = None
            if getattr(req, 'is_json', False) and getattr(req, 'json', None):
                device_id = req.json.get('device_id')
            elif hasattr(req, 'args') and 'device_id' in req.args:
                device_id = req.args.get('device_id')

            if not device_id:
                logger.warning(f"Missing device_id in request to {request.endpoint}")
                resp = jsonify({'error': 'Device ID required', 'code': 'MISSING_DEVICE_ID'})
                return resp if isinstance(resp, tuple) else (resp, 400)

            logger.debug(f"Device access request: tenant={tenant_id}, device={device_id}")

            if has_request_context():
                flask_g.device_id = device_id

            return func(*args, **kwargs)

        return decorated_function


def setup_tenant_middleware(app, auth_config: AuthConfig, audit_service=None):
    middleware = TenantMiddleware(auth_config, audit_service)

    # Store middleware in app context for access in routes
    app.tenant_middleware = middleware

    @app.before_request
    def setup_tenant_context():
        tenant_id = middleware.extract_tenant_id(get_request())
        if tenant_id and has_request_context():
            flask_g.tenant_id = tenant_id

    return middleware


def require_tenant(func: Callable) -> Callable:
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not hasattr(current_app, 'tenant_middleware'):
            logger.warning("Tenant middleware not configured")
            resp = jsonify({'error': 'Tenant middleware not configured'})
            return resp if isinstance(resp, tuple) else (resp, 500)
        return current_app.tenant_middleware.require_tenant(func)(*args, **kwargs)

    return decorated_function


def enforce_tenant_isolation(func: Callable) -> Callable:
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not hasattr(current_app, 'tenant_middleware'):
            logger.warning("Tenant middleware not configured")
            resp = jsonify({'error': 'Tenant middleware not configured'})
            return resp if isinstance(resp, tuple) else (resp, 500)
        return current_app.tenant_middleware.enforce_tenant_isolation(func)(*args, **kwargs)

    return decorated_function


def require_device_access(func: Callable) -> Callable:
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not hasattr(current_app, 'tenant_middleware'):
            logger.warning("Tenant middleware not configured")
            resp = jsonify({'error': 'Tenant middleware not configured'})
            return resp if isinstance(resp, tuple) else (resp, 500)
        return current_app.tenant_middleware.require_device_access(func)(*args, **kwargs)

    return decorated_function


__all__ = [
    "TenantMiddleware",
    "setup_tenant_middleware",
    "require_tenant",
    "enforce_tenant_isolation",
    "require_device_access",
]


