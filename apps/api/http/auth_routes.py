"""Authentication endpoints using request-scoped dependencies."""

from __future__ import annotations

import os
from flask import Blueprint, jsonify, request, current_app
import time

from apps.api.http.middleware import require_auth


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/auth/login", methods=["POST"])
def auth_login():
    cfg = getattr(request, "auth_config", None)
    if not cfg or not getattr(cfg, "auth_enabled", False):
        return jsonify({"error": "Authentication disabled"}), 503

    try:
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return jsonify({"error": "Missing required fields", "code": "MISSING_FIELDS"}), 400

        limiter = getattr(request, "rate_limiter", None)
        audit = getattr(request, "audit_logger", None)
        sessions = getattr(request, "session_manager", None)
        users = current_app.config.get("user_manager")

        allowed, message = limiter.is_allowed(request.remote_addr, username) if limiter else (True, "Allowed")
        if not allowed:
            if audit:
                audit.log_auth_failure(username, request.remote_addr, "RATE_LIMITED")
            return jsonify({"error": message, "code": "RATE_LIMITED"}), 429

        user = users.authenticate_user(username, password) if users else None
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

        session = sessions.create_session(username, user.role, request) if sessions else None
        if users:
            users.update_last_login(username)
        if limiter:
            limiter.clear_attempts(request.remote_addr, username)
        if audit and session:
            audit.log_auth_success(username, request.remote_addr, session.session_id)

        resp = jsonify({
            "status": "success",
            "expires_in": cfg.session_timeout,
            "user": {"username": username, "role": user.role},
        })
        if session:
            resp.set_cookie(
                "bas_session_id",
                session.session_id,
                max_age=cfg.session_timeout,
                httponly=True,
                secure=True,
                samesite="Strict",
            )
        return resp
    except Exception:
        return jsonify({"error": "Internal server error"}), 500


@auth_bp.route("/auth/logout", methods=["POST"])
def auth_logout():
    try:
        sessions = getattr(request, "session_manager", None)
        audit = getattr(request, "audit_logger", None)
        sid = request.cookies.get("bas_session_id")
        if not sid:
            data = request.get_json() or {}
            sid = data.get("session_id")
        if sid:
            if sessions:
                sessions.invalidate_session(sid)
            if audit:
                audit.log_session_destruction(sid)
        resp = jsonify({"status": "success", "message": "Logged out successfully"})
        resp.set_cookie("bas_session_id", "", max_age=0, httponly=True, secure=True, samesite="Strict")
        return resp
    except Exception:
        return jsonify({"error": "Internal server error"}), 500


@auth_bp.route("/auth/status")
def auth_status():
    sessions = getattr(request, "session_manager", None)
    sid = request.cookies.get("bas_session_id") or request.headers.get("X-Session-ID")
    if not sid:
        return jsonify({"error": "No session provided", "code": "NO_SESSION"}), 400
    session = sessions.validate_session(sid, request) if sessions else None
    if not session:
        return jsonify({"error": "Invalid or expired session", "code": "SESSION_INVALID"}), 401
    return jsonify({
        "status": "valid",
        "user": {"username": session.username, "role": session.role, "login_time": session.created_at},
        "expires_in": int(session.expires_at - time.time()) if hasattr(session, "expires_at") else 0,
    })


@auth_bp.route("/auth/limits", methods=["POST"])
@require_auth(required_role="admin")
def update_per_user_limits():
    try:
        api_key = os.getenv("DYNAMIC_LIMIT_API_KEY", "").strip()
        if api_key:
            provided = (request.headers.get("X-Limits-Key") or "").strip()
            if provided != api_key:
                return jsonify({"error": "Forbidden", "code": "FORBIDDEN"}), 403
        body = request.get_json() or {}
        limits = body.get("per_user_limits") if isinstance(body, dict) else None
        if not isinstance(limits, dict):
            return jsonify({"error": "Invalid payload", "code": "INVALID_ARGUMENT"}), 400
        holder = current_app.config.get("rate_limit_holder")
        snap = holder.update(per_user_limits=limits)
        snapshot = snap.get_per_user_limits_snapshot()
        return jsonify({"per_user_limits": snapshot}), 200
    except Exception as exc:
        return jsonify({"error": "Internal server error"}), 500


