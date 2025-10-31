"""Tenant middleware.

Implements tenant context setup and decorators.
"""

from __future__ import annotations

import hashlib
import time
import threading
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Dict, Optional, Protocol, runtime_checkable

from flask import Request, current_app, g, has_request_context, jsonify
from flask import request as flask_request

from logging_lib import get_logger as get_structured_logger

from app_platform.config.auth import AuthConfig


logger = get_structured_logger("api.http.middleware.tenant")


@runtime_checkable
class TenantAuditSink(Protocol):
    """Contract for audit sinks used by tenant middleware."""

    def log_permission_denied(
        self,
        *,
        username: Optional[str],
        user_id: Optional[str],
        ip_address: Optional[str],
        resource: Optional[str],
        reason: str,
    ) -> Any:
        ...

    def log_tenant_violation(
        self,
        *,
        user_id: Optional[str],
        username: Optional[str],
        ip_address: Optional[str],
        attempted_tenant: Optional[str],
        allowed_tenant: Optional[str],
    ) -> Any:
        ...


def _scrub_identifier(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:12]


def get_request():
    """Return patched request if provided, else real Flask request proxy."""
    return flask_request


@dataclass(frozen=True)
class TenantContext:
    tenant_id: Optional[str]
    source: str
    principal_hash: Optional[str]
    header_tenant: Optional[str]
    session_tenant: Optional[str]
    from_cache: bool = False
    conflict: bool = False


class TenantResolver:
    """Determine tenant context for a request with lightweight caching."""

    def __init__(
        self,
        tenant_header: str,
        *,
        cache_ttl_s: int = 120,
        cache_capacity: int = 1024,
    ) -> None:
        self._tenant_header = tenant_header
        self._cache_ttl_s = max(1, int(cache_ttl_s))
        self._cache_capacity = max(1, int(cache_capacity))
        self._cache: Dict[str, tuple[str, float]] = {}
        self._lock = threading.RLock()

    def resolve(self, req: Request) -> TenantContext:
        principal_id = self._extract_principal(req)
        header_tenant = self._safe_header(req)
        session_tenant = self._safe_session_tenant(req)
        principal_hash = _scrub_identifier(principal_id)

        cached_tenant = self._cache_get(principal_id)
        if cached_tenant is not None:
            return TenantContext(
                tenant_id=cached_tenant,
                source="cache",
                principal_hash=principal_hash,
                header_tenant=header_tenant,
                session_tenant=session_tenant,
                from_cache=True,
                conflict=False,
            )

        tenant_id = None
        source = "none"
        conflict = False

        if session_tenant:
            tenant_id = session_tenant
            source = "session"
            self._cache_set(principal_id, tenant_id)
            if header_tenant and header_tenant != tenant_id:
                conflict = True
        elif header_tenant:
            tenant_id = header_tenant
            source = "header"

        return TenantContext(
            tenant_id=tenant_id,
            source=source,
            principal_hash=principal_hash,
            header_tenant=header_tenant,
            session_tenant=session_tenant,
            from_cache=False,
            conflict=conflict,
        )

    def _extract_principal(self, req: Request) -> Optional[str]:
        try:
            header_sid = req.headers.get("X-Session-ID")
        except Exception:
            header_sid = None

        try:
            cookie_sid = req.cookies.get("bas_session_id") if hasattr(req, "cookies") else None
        except Exception:
            cookie_sid = None

        return header_sid or cookie_sid

    def _safe_header(self, req: Request) -> Optional[str]:
        try:
            return req.headers.get(self._tenant_header)
        except Exception:
            return None

    def _safe_session_tenant(self, req: Request) -> Optional[str]:
        try:
            session_obj = getattr(req, "session", None)
            return getattr(session_obj, "tenant_id", None) if session_obj else None
        except Exception:
            return None

    def _cache_get(self, principal: Optional[str]) -> Optional[str]:
        if not principal:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._cache.get(principal)
            if not entry:
                return None
            tenant_id, expires_at = entry
            if expires_at < now:
                self._cache.pop(principal, None)
                return None
            return tenant_id

    def _cache_set(self, principal: Optional[str], tenant_id: Optional[str]) -> None:
        if not principal or not tenant_id:
            return
        expiry = time.monotonic() + float(self._cache_ttl_s)
        with self._lock:
            if len(self._cache) >= self._cache_capacity:
                now = time.monotonic()
                expired = [key for key, (_, exp) in self._cache.items() if exp < now]
                for key in expired:
                    self._cache.pop(key, None)
                if len(self._cache) >= self._cache_capacity:
                    try:
                        self._cache.pop(next(iter(self._cache)))
                    except StopIteration:
                        pass
            self._cache[principal] = (tenant_id, expiry)


class TenantMiddleware:
    """Middleware for enforcing multi-tenant isolation."""

    def __init__(
        self,
        auth_config: AuthConfig,
        audit_sink: Optional[TenantAuditSink] = None,
    ) -> None:
        self.auth_config = auth_config
        self.tenant_header = auth_config.tenant_id_header
        self._resolver = TenantResolver(
            self.tenant_header,
            cache_ttl_s=120,
            cache_capacity=1024,
        )
        if audit_sink is None:
            self._audit_sink: Optional[TenantAuditSink] = None
        else:
            missing = [
                name
                for name in ("log_permission_denied", "log_tenant_violation")
                if not hasattr(audit_sink, name)
            ]
            if missing:
                logger.warning(
                    "Provided audit sink is missing required methods",
                    extra={"missing": missing},
                )
                self._audit_sink = None
            else:
                self._audit_sink = audit_sink  # type: ignore[assignment]

    def _attach_context(self, request_obj: Request, context: TenantContext) -> None:
        try:
            setattr(request_obj, "_tenant_context", context)
        except Exception:
            pass
        try:
            setattr(request_obj, "tenant_id", context.tenant_id)
        except Exception:
            pass
        if has_request_context() and context.tenant_id is not None:
            try:
                g.tenant_id = context.tenant_id
            except Exception:
                pass

    def _handle_conflict(self, request_obj: Request, context: TenantContext) -> None:
        if not context.conflict:
            return

        logger.warning(
            "Tenant header mismatch; using session tenant",
            extra={
                "endpoint": getattr(request_obj, "endpoint", "unknown"),
                "header_tenant": context.header_tenant,
                "session_tenant": context.session_tenant,
                "principal_hash": context.principal_hash,
            },
        )

        if not self._audit_sink:
            return

        try:
            session_obj = getattr(request_obj, "session", None)
            self._audit_sink.log_tenant_violation(
                user_id=getattr(session_obj, "user_id", None),
                username=getattr(session_obj, "username", None),
                ip_address=getattr(request_obj, "remote_addr", ""),
                attempted_tenant=context.header_tenant,
                allowed_tenant=context.session_tenant,
            )
        except Exception as exc:
            logger.error(
                "Failed to audit tenant header conflict",
                extra={"error": str(exc)},
            )

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

        existing_context = getattr(request_obj, "_tenant_context", None)
        if isinstance(existing_context, TenantContext):
            self._attach_context(request_obj, existing_context)
            self._handle_conflict(request_obj, existing_context)
            return existing_context.tenant_id

        context = self._resolver.resolve(request_obj)
        self._attach_context(request_obj, context)
        self._handle_conflict(request_obj, context)

        return context.tenant_id

    def extract_tenant_id(self, request) -> Optional[str]:
        """Extract tenant ID using cached value or from session/header."""
        # Prefer cached value
        try:
            context = getattr(request, "_tenant_context", None)
        except Exception:
            context = None

        if isinstance(context, TenantContext):
            return context.tenant_id

        context = self._resolver.resolve(request)
        self._attach_context(request, context)
        self._handle_conflict(request, context)
        return context.tenant_id

    def validate_tenant_access(self, user_tenant_id: str, requested_tenant_id: str) -> bool:
        return user_tenant_id == requested_tenant_id

    def audit_tenant_violation(
        self,
        user_id: Optional[str],
        username: Optional[str],
        ip_address: str,
        attempted_tenant: str,
        allowed_tenant: str,
    ) -> None:
        if not self._audit_sink:
            return
        try:
            self._audit_sink.log_tenant_violation(
                user_id=user_id,
                username=username,
                ip_address=ip_address,
                attempted_tenant=attempted_tenant,
                allowed_tenant=allowed_tenant,
            )
        except Exception as exc:
            logger.error(
                "Failed to audit tenant violation",
                extra={"error": str(exc)},
            )

    def require_tenant(self, func: Callable) -> Callable:
        @wraps(func)
        def decorated_function(*args, **kwargs):
            req = get_request()
            tenant_id = self.extract_tenant_id(req)
            if not tenant_id:
                logger.warning(
                    "Missing tenant ID in request",
                    extra={"endpoint": getattr(req, "endpoint", None)},
                )
                self._log_permission_denied(request=req, reason="MISSING_TENANT_ID")
                resp = jsonify({'error': 'Tenant ID required', 'code': 'MISSING_TENANT_ID'})
                return resp if isinstance(resp, tuple) else (resp, 400)

            if has_request_context():
                g.tenant_id = tenant_id

            return func(*args, **kwargs)

        return decorated_function

    def enforce_tenant_isolation(self, func: Callable) -> Callable:
        @wraps(func)
        def decorated_function(*args, **kwargs):
            req = get_request()
            requested_tenant_id = self.extract_tenant_id(req)
            if not requested_tenant_id:
                logger.warning(
                    "Missing tenant ID in request",
                    extra={"endpoint": getattr(req, 'endpoint', None)},
                )
                resp = jsonify({'error': 'Tenant ID required', 'code': 'MISSING_TENANT_ID'})
                return resp if isinstance(resp, tuple) else (resp, 400)

            user_tenant_id = None
            if hasattr(req, 'session') and req.session:
                user_tenant_id = getattr(req.session, 'tenant_id', None)

            if not user_tenant_id:
                logger.warning(
                    "No user session for tenant-isolated endpoint",
                    extra={"endpoint": getattr(req, 'endpoint', None)},
                )
                if has_request_context():
                    g.tenant_id = requested_tenant_id
                return func(*args, **kwargs)

            if not self.validate_tenant_access(user_tenant_id, requested_tenant_id):
                logger.warning(
                    "Tenant violation",
                    extra={
                        "endpoint": getattr(req, 'endpoint', None),
                        "user_hash": _scrub_identifier(getattr(getattr(req, 'session', None), 'username', None)),
                        "attempted_tenant": requested_tenant_id,
                        "allowed_tenant": user_tenant_id,
                    },
                )

                self.audit_tenant_violation(
                    user_id=getattr(getattr(req, 'session', None), 'user_id', None),
                    username=getattr(getattr(req, 'session', None), 'username', None),
                    ip_address=getattr(req, 'remote_addr', ''),
                    attempted_tenant=requested_tenant_id,
                    allowed_tenant=user_tenant_id
                )

                resp = jsonify({'error': 'Access denied to tenant', 'code': 'TENANT_ACCESS_DENIED'})
                return resp if isinstance(resp, tuple) else (resp, 403)

            if has_request_context():
                g.tenant_id = requested_tenant_id

            return func(*args, **kwargs)

        return decorated_function

    def _log_permission_denied(self, *, request: Request, reason: str) -> None:
        if not self._audit_sink:
            return
        session_obj = getattr(request, 'session', None)
        username = getattr(session_obj, 'username', None)
        user_id = getattr(session_obj, 'user_id', None)
        try:
            self._audit_sink.log_permission_denied(
                username=username,
                user_id=user_id,
                ip_address=getattr(request, 'remote_addr', ''),
                resource=getattr(request, 'endpoint', None),
                reason=reason,
            )
        except Exception as exc:
            logger.error(
                "Failed to audit permission denied",
                extra={"error": str(exc)},
            )

    def require_device_access(self, func: Callable) -> Callable:
        @wraps(func)
        def decorated_function(*args, **kwargs):
            try:
                tenant_id = getattr(g, 'tenant_id', None)
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
            elif hasattr(req, 'view_args') and isinstance(req.view_args, dict):
                device_id = req.view_args.get('device_id') or req.view_args.get('deviceId')

            if not device_id:
                logger.warning(
                    "Missing device_id in request",
                    extra={"endpoint": getattr(req, 'endpoint', None)},
                )
                resp = jsonify({'error': 'Device ID required', 'code': 'MISSING_DEVICE_ID'})
                return resp if isinstance(resp, tuple) else (resp, 400)

            logger.debug(
                "Device access request",
                extra={
                    "tenant": tenant_id,
                    "device_hash": _scrub_identifier(str(device_id) if device_id else None),
                },
            )

            if has_request_context():
                g.device_id = device_id

            return func(*args, **kwargs)

        return decorated_function


def setup_tenant_middleware(app, auth_config: AuthConfig, audit_sink=None):
    middleware = TenantMiddleware(auth_config, audit_sink)

    # Store middleware in app context for access in routes
    app.tenant_middleware = middleware

    @app.before_request
    def setup_tenant_context():
        req = get_request()
        middleware.setup_tenant_context(req)

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
    "TenantAuditSink",
    "TenantContext",
    "TenantResolver",
    "TenantMiddleware",
    "setup_tenant_middleware",
    "require_tenant",
    "enforce_tenant_isolation",
    "require_device_access",
]


