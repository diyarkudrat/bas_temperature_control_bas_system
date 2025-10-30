"""Authentication routes served by the standalone auth service.

All stateful collaborators (sessions, users, rate limit holder) are injected per
request by ``apps.auth_service.main`` so the module remains side-effect free and
safe under multi-process runtimes.
"""

from __future__ import annotations

import os
import time
from typing import Any, Tuple

from flask import Blueprint, current_app, jsonify, request


auth_bp = Blueprint("auth_service", __name__)


def _get_request_components() -> Tuple[Any, Any, Any, Any, Any]:
    """Best-effort helpers for pulling dependencies from the request context."""

    limiter = getattr(request, "rate_limiter", None)
    audit = getattr(request, "audit_logger", None)
    sessions = getattr(request, "session_manager", None)
    users = getattr(request, "user_manager", None)
    holder = getattr(request, "rate_limit_holder", None)
    return limiter, audit, sessions, users, holder


def _service_token_valid() -> bool:
    """Placeholder auth for service-to-service endpoints.

    TODO: Replace with signed service token verification (patch plan item #3).
    """

    expected = os.getenv("AUTH_SERVICE_SHARED_TOKEN", "").strip()
    if not expected:
        return False
    provided = (request.headers.get("X-Service-Token") or "").strip()
    return bool(provided and provided == expected)


@auth_bp.route("/auth/login", methods=["POST"])
def auth_login():
    cfg = getattr(request, "auth_config", None)
    if not cfg or not getattr(cfg, "auth_enabled", False):
        return jsonify({"error": "Authentication disabled"}), 503

    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    if not username or not password:
        return jsonify({"error": "Missing required fields", "code": "MISSING_FIELDS"}), 400

    limiter, audit, sessions, users, _ = _get_request_components()
    if sessions is None or users is None:
        current_app.logger.error("Auth runtime not fully initialized")
        return jsonify({"error": "Authentication system unavailable"}), 500

    try:
        allowed, message = limiter.is_allowed(request.remote_addr, username) if limiter else (True, "Allowed")
        if not allowed:
            if audit:
                audit.log_auth_failure(username, request.remote_addr, "RATE_LIMITED")
            return jsonify({"error": message, "code": "RATE_LIMITED"}), 429

        user = users.authenticate_user(username, password)
        if not user:
            if limiter:
                limiter.record_attempt(request.remote_addr, username)
            if audit:
                audit.log_auth_failure(username, request.remote_addr, "INVALID_CREDENTIALS")
            return jsonify({"error": "Invalid credentials", "code": "AUTH_FAILED"}), 401

        if user.is_locked():
            if audit:
                audit.log_auth_failure(username, request.remote_addr, "ACCOUNT_LOCKED")
            return jsonify({"error": "Account locked", "code": "USER_LOCKED"}), 423

        session = sessions.create_session(username, user.role, request)
        users.update_last_login(username)
        if limiter:
            limiter.clear_attempts(request.remote_addr, username)
        if audit:
            audit.log_auth_success(username, request.remote_addr, session.session_id)

        resp = jsonify({
            "status": "success",
            "expires_in": cfg.session_timeout,
            "user": {
                "username": username,
                "role": user.role,
                "user_id": getattr(session, "user_id", "unknown"),
                "tenant_id": getattr(session, "tenant_id", None),
            },
        })
        resp.set_cookie(
            "bas_session_id",
            session.session_id,
            max_age=cfg.session_timeout,
            httponly=True,
            secure=True,
            samesite="Strict",
        )
        return resp
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Auth login failed: %%s", exc)
        return jsonify({"error": "Internal server error"}), 500


@auth_bp.route("/auth/logout", methods=["POST"])
def auth_logout():
    _, audit, sessions, _, _ = _get_request_components()
    if sessions is None:
        current_app.logger.error("Session manager missing in logout handler")
        return jsonify({"error": "Authentication system unavailable"}), 500

    try:
        sid = request.cookies.get("bas_session_id")
        if not sid:
            payload = request.get_json(silent=True) or {}
            sid = payload.get("session_id")

        if sid:
            sessions.invalidate_session(sid)
            if audit:
                audit.log_session_destruction(sid)

        resp = jsonify({"status": "success", "message": "Logged out successfully"})
        resp.set_cookie("bas_session_id", "", max_age=0, httponly=True, secure=True, samesite="Strict")
        return resp
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Auth logout failed: %%s", exc)
        return jsonify({"error": "Internal server error"}), 500


@auth_bp.route("/auth/status", methods=["GET"])
def auth_status():
    _, _, sessions, _, _ = _get_request_components()
    if sessions is None:
        current_app.logger.error("Session manager missing in status handler")
        return jsonify({"error": "Authentication system unavailable"}), 500

    sid = request.cookies.get("bas_session_id") or request.headers.get("X-Session-ID")
    if not sid:
        return jsonify({"error": "No session provided", "code": "NO_SESSION"}), 400

    try:
        session = sessions.validate_session(sid, request)
        if not session:
            return jsonify({"error": "Invalid or expired session", "code": "SESSION_INVALID"}), 401

        return jsonify({
            "status": "valid",
            "user": {
                "username": session.username,
                "role": session.role,
                "login_time": session.created_at,
                "user_id": getattr(session, "user_id", "unknown"),
                "tenant_id": getattr(session, "tenant_id", None),
            },
            "expires_in": int(session.expires_at - time.time()) if hasattr(session, "expires_at") else 0,
        })
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Auth status failed: %%s", exc)
        return jsonify({"error": "Internal server error"}), 500


@auth_bp.route("/auth/limits", methods=["POST"])
def update_per_user_limits():
    _, _, _, _, holder = _get_request_components()
    if holder is None:
        holder = current_app.config.get("rate_limit_holder")
    if holder is None:
        current_app.logger.error("Rate limit holder unavailable")
        return jsonify({"error": "Rate limit holder unavailable"}), 500

    if not _service_token_valid():
        return jsonify({"error": "Forbidden", "code": "FORBIDDEN"}), 403

    try:
        body = request.get_json(silent=True) or {}
        limits = body.get("per_user_limits") if isinstance(body, dict) else None
        if not isinstance(limits, dict):
            return jsonify({"error": "Invalid payload", "code": "INVALID_ARGUMENT"}), 400

        snap = holder.update(per_user_limits=limits)
        snapshot = snap.get_per_user_limits_snapshot()
        return jsonify({"per_user_limits": snapshot}), 200
    except ValueError as exc:
        return jsonify({"error": str(exc), "code": "INVALID_ARGUMENT"}), 400
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Updating per-user limits failed: %%s", exc)
        return jsonify({"error": "Internal server error"}), 500

