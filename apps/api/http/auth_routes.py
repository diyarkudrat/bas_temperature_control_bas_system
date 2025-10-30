"""Authentication endpoints delegating to the standalone auth service."""

from __future__ import annotations

import os
from typing import Callable, Optional

from flask import Blueprint, current_app, jsonify, request

from apps.api.http.middleware import require_auth
from apps.api.clients import AuthServiceClient


auth_bp = Blueprint("auth", __name__)


def _get_auth_client() -> Optional[AuthServiceClient]:
    """Resolve an auth service client using request-scoped wiring."""

    direct = getattr(request, "auth_service_client", None)
    if isinstance(direct, AuthServiceClient):
        return direct

    cached = getattr(request, "_auth_service_client", None)
    if isinstance(cached, AuthServiceClient):
        return cached

    factory: Optional[Callable[[], AuthServiceClient]] = current_app.config.get("auth_service_client_factory")
    if callable(factory):
        client = factory()
        setattr(request, "_auth_service_client", client)
        return client

    fallback = current_app.config.get("auth_service_client")
    if isinstance(fallback, AuthServiceClient):
        return fallback

    return None


def _forward_response(client_resp, *, default_error: str = "Auth service unavailable", default_code: str = "AUTH_UPSTREAM_ERROR"):
    payload = client_resp.json if client_resp and client_resp.json is not None else {"error": default_error, "code": default_code}
    flask_resp = jsonify(payload)
    if client_resp:
        for header, value in client_resp.headers.items():
            header_lc = header.lower()
            if header_lc in {"content-length", "transfer-encoding", "connection", "content-type", "set-cookie"}:
                continue
            flask_resp.headers[header] = value
        for cookie_header in getattr(client_resp, "set_cookies", ()):  # type: ignore[attr-defined]
            flask_resp.headers.add("Set-Cookie", cookie_header)
    return flask_resp, getattr(client_resp, "status_code", 502)


@auth_bp.route("/auth/login", methods=["POST"])
def auth_login():
    cfg = getattr(request, "auth_config", None)
    if not cfg or not getattr(cfg, "auth_enabled", False):
        return jsonify({"error": "Authentication disabled"}), 503

    client = _get_auth_client()
    if client is None:
        return jsonify({"error": "Auth service client unavailable"}), 503

    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Missing required fields", "code": "MISSING_FIELDS"}), 400

    tenant_header = getattr(cfg, "tenant_id_header", "X-BAS-Tenant")
    tenant_id = request.headers.get(tenant_header)

    try:
        upstream = client.login(
            username=username,
            password=password,
            tenant_id=tenant_id,
            remote_addr=request.remote_addr,
        )
    except ConnectionError:
        current_app.logger.error("Auth service login request failed", exc_info=True)
        return jsonify({"error": "Auth service unreachable", "code": "AUTH_UPSTREAM_UNAVAILABLE"}), 502

    if upstream.status_code == 401:
        current_app.logger.info("Auth login denied for %s", username)

    return _forward_response(upstream)


@auth_bp.route("/auth/logout", methods=["POST"])
def auth_logout():
    client = _get_auth_client()
    if client is None:
        return jsonify({"error": "Auth service client unavailable"}), 503

    payload = request.get_json(silent=True) or {}
    sid = request.cookies.get("bas_session_id") or payload.get("session_id")

    try:
        upstream = client.logout(
            session_id=sid,
            cookies=dict(request.cookies) if request.cookies else None,
        )
    except ConnectionError:
        current_app.logger.error("Auth service logout request failed", exc_info=True)
        return jsonify({"error": "Auth service unreachable", "code": "AUTH_UPSTREAM_UNAVAILABLE"}), 502

    return _forward_response(upstream)


@auth_bp.route("/auth/status")
def auth_status():
    client = _get_auth_client()
    if client is None:
        return jsonify({"error": "Auth service client unavailable"}), 503

    sid = request.cookies.get("bas_session_id") or request.headers.get("X-Session-ID")
    if not sid:
        return jsonify({"error": "No session provided", "code": "NO_SESSION"}), 400

    try:
        upstream = client.status(
            session_id=sid,
            cookies=dict(request.cookies) if request.cookies else None,
        )
    except ConnectionError:
        current_app.logger.error("Auth service status request failed", exc_info=True)
        return jsonify({"error": "Auth service unreachable", "code": "AUTH_UPSTREAM_UNAVAILABLE"}), 502

    return _forward_response(upstream)


@auth_bp.route("/auth/limits", methods=["POST"])
@require_auth(required_role="admin")
def update_per_user_limits():
    api_key = os.getenv("DYNAMIC_LIMIT_API_KEY", "").strip()
    if api_key:
        provided = (request.headers.get("X-Limits-Key") or "").strip()
        if provided != api_key:
            return jsonify({"error": "Forbidden", "code": "FORBIDDEN"}), 403

    body = request.get_json(silent=True) or {}
    limits = body.get("per_user_limits") if isinstance(body, dict) else None
    if not isinstance(limits, dict):
        return jsonify({"error": "Invalid payload", "code": "INVALID_ARGUMENT"}), 400

    client = _get_auth_client()
    if client is None:
        return jsonify({"error": "Auth service client unavailable"}), 503

    try:
        upstream = client.update_limits(per_user_limits=limits)
    except ConnectionError:
        current_app.logger.error("Auth service limits request failed", exc_info=True)
        return jsonify({"error": "Auth service unreachable", "code": "AUTH_UPSTREAM_UNAVAILABLE"}), 502

    if upstream.ok and upstream.json:
        snapshot = upstream.json.get("per_user_limits")
        holder = current_app.config.get("rate_limit_holder")
        if holder and isinstance(snapshot, dict):
            try:
                holder.update(per_user_limits=snapshot)
            except Exception:
                current_app.logger.warning("Failed to apply per-user limits locally", exc_info=True)

    return _forward_response(upstream)


