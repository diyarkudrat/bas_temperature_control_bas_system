"""Backward-compatible authentication middleware helpers.

Historically the test suite imported helpers from `auth.middleware`. The new
codebase hosts the implementations under `apps.api.http.middleware`. This
module re-exports the modern implementations and adds thin shims so the legacy
imports continue to work.
"""

from __future__ import annotations

from typing import Any, Dict

from flask import jsonify, request

from logging_lib import get_logger

from domains.auth.exceptions import AuthError

from apps.api.http.middleware.auth import (
    _audit_auth_failure,
    _audit_permission_denied,
    _audit_tenant_violation,
    _ensure_tenant_isolation as _ensure_tenant_isolation_impl,
    _has_permission,
    require_auth,
)
from apps.api.http.middleware.security import add_security_headers

__all__ = [
    "require_auth",
    "add_security_headers",
    "log_request_info",
    "handle_auth_error",
    "_has_permission",
    "_enforce_tenant_isolation",
    "_audit_auth_failure",
    "_audit_permission_denied",
    "_audit_tenant_violation",
]

_LOGGER = get_logger("auth.middleware.compat")


def log_request_info() -> None:
    """Log useful request attributes for diagnostics without raising errors."""

    try:
        info: Dict[str, Any] = {
            "method": getattr(request, "method", None),
            "path": getattr(request, "path", None),
            "remote_addr": getattr(request, "remote_addr", None),
        }
        if hasattr(request, "headers"):
            info["user_agent"] = request.headers.get("User-Agent")

        # Filter out falsy values so log output stays concise.
        payload = {k: v for k, v in info.items() if v}
        if payload:
            _LOGGER.debug("auth_request_info", extra=payload)
        else:
            _LOGGER.debug("auth_request_info", extra={"detail": "no request metadata"})
    except Exception as exc:  # pragma: no cover - defensive logging path
        _LOGGER.debug("auth_request_info_failed", extra={"error": str(exc)})


def handle_auth_error(error: Exception):
    """Translate authentication errors into standardized HTTP responses."""

    if isinstance(error, AuthError):
        return (
            jsonify(
                {
                    "error": "Authentication failed",
                    "code": "AUTH_ERROR",
                    "message": str(error),
                }
            ),
            401,
        )

    return (
        jsonify(
            {
                "error": "Internal server error",
                "code": "INTERNAL_ERROR",
                "message": str(error),
            }
        ),
        500,
    )


def _enforce_tenant_isolation(session_obj: Any):
    """Compatibility alias for the tenant isolation helper."""

    return _ensure_tenant_isolation_impl(session_obj)


