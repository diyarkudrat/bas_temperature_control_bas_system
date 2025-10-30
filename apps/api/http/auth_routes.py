"""Authentication endpoints delegating to the standalone auth service."""

from __future__ import annotations

import hashlib
import os
from typing import Callable, Optional

from flask import Blueprint, current_app, jsonify, request

from logging_lib import get_logger as get_structured_logger

from apps.api.http.middleware import require_auth
from apps.api.clients import AuthServiceClient


auth_bp = Blueprint("auth", __name__)

logger = get_structured_logger("api.http.auth")
upstream_logger = get_structured_logger("api.http.auth.upstream")
limits_logger = get_structured_logger("api.http.auth.limits")


def _scrub_identifier(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:12]


def _get_auth_client() -> Optional[AuthServiceClient]:
    """Resolve an auth service client using request-scoped wiring."""

    direct = getattr(request, "auth_service_client", None)
    if isinstance(direct, AuthServiceClient):
        upstream_logger.debug("Using request-scoped auth service client")
        return direct

    cached = getattr(request, "_auth_service_client", None)
    if isinstance(cached, AuthServiceClient):
        upstream_logger.debug("Using cached auth service client on request")
        return cached

    factory: Optional[Callable[[], AuthServiceClient]] = current_app.config.get("auth_service_client_factory")
    if callable(factory):
        client = factory()
        setattr(request, "_auth_service_client", client)
        upstream_logger.debug("Auth service client created from factory")
        return client

    fallback = current_app.config.get("auth_service_client")
    if isinstance(fallback, AuthServiceClient):
        upstream_logger.warning("Using fallback auth service client from app config")
        return fallback

    upstream_logger.error("Auth service client unavailable")
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
    status_code = getattr(client_resp, "status_code", 502)
    upstream_logger.info(
        "Forwarding auth service response",
        extra={
            "status_code": status_code,
            "path": request.path,
            "method": request.method,
            "success": bool(client_resp and 200 <= status_code < 400),
        },
    )
    return flask_resp, status_code


@auth_bp.route("/auth/login", methods=["POST"])
def auth_login():
    cfg = getattr(request, "auth_config", None)
    if not cfg or not getattr(cfg, "auth_enabled", False):
        logger.warning("Auth login request rejected: auth disabled", extra={"config_present": cfg is not None})
        return jsonify({"error": "Authentication disabled"}), 503

    client = _get_auth_client()
    if client is None:
        upstream_logger.error("Auth login request failed: client unavailable")
        return jsonify({"error": "Auth service client unavailable"}), 503

    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        logger.warning("Auth login missing credentials", extra={"username_present": bool(username)})
        return jsonify({"error": "Missing required fields", "code": "MISSING_FIELDS"}), 400

    username_hash = _scrub_identifier(username)
    remote_hash = _scrub_identifier(request.remote_addr)
    logger.info(
        "Auth login attempt received",
        extra={"username_hash": username_hash, "remote_hash": remote_hash},
    )

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
        upstream_logger.error("Auth service login request failed", exc_info=True)
        return jsonify({"error": "Auth service unreachable", "code": "AUTH_UPSTREAM_UNAVAILABLE"}), 502

    if upstream.status_code == 401:
        logger.info(
            "Auth login denied",
            extra={"username_hash": username_hash},
        )

    return _forward_response(upstream)


@auth_bp.route("/auth/logout", methods=["POST"])
def auth_logout():
    client = _get_auth_client()
    if client is None:
        upstream_logger.error("Auth logout request failed: client unavailable")
        return jsonify({"error": "Auth service client unavailable"}), 503

    payload = request.get_json(silent=True) or {}
    sid = request.cookies.get("bas_session_id") or payload.get("session_id")
    sid_hash = _scrub_identifier(sid) if sid else None
    logger.info(
        "Auth logout requested",
        extra={"session_present": bool(sid)},
    )

    try:
        upstream = client.logout(
            session_id=sid,
            cookies=dict(request.cookies) if request.cookies else None,
        )
    except ConnectionError:
        upstream_logger.error("Auth service logout request failed", exc_info=True)
        return jsonify({"error": "Auth service unreachable", "code": "AUTH_UPSTREAM_UNAVAILABLE"}), 502

    logger.info(
        "Auth logout forwarded",
        extra={"session_hash": sid_hash, "upstream_status": getattr(upstream, "status_code", None)},
    )
    return _forward_response(upstream)


@auth_bp.route("/auth/status")
def auth_status():
    client = _get_auth_client()
    if client is None:
        upstream_logger.error("Auth status request failed: client unavailable")
        return jsonify({"error": "Auth service client unavailable"}), 503

    sid = request.cookies.get("bas_session_id") or request.headers.get("X-Session-ID")
    if not sid:
        logger.info("Auth status request missing session identifier")
        return jsonify({"error": "No session provided", "code": "NO_SESSION"}), 400

    sid_hash = _scrub_identifier(sid)
    logger.info(
        "Auth status check forwarding",
        extra={"session_hash": sid_hash},
    )

    try:
        upstream = client.status(
            session_id=sid,
            cookies=dict(request.cookies) if request.cookies else None,
        )
    except ConnectionError:
        upstream_logger.error("Auth service status request failed", exc_info=True)
        return jsonify({"error": "Auth service unreachable", "code": "AUTH_UPSTREAM_UNAVAILABLE"}), 502

    return _forward_response(upstream)


@auth_bp.route("/auth/limits", methods=["POST"])
@require_auth(required_role="admin")
def update_per_user_limits():
    api_key = os.getenv("DYNAMIC_LIMIT_API_KEY", "").strip()
    if api_key:
        provided = (request.headers.get("X-Limits-Key") or "").strip()
        if provided != api_key:
            limits_logger.warning("Limits update forbidden: invalid API key")
            return jsonify({"error": "Forbidden", "code": "FORBIDDEN"}), 403

    body = request.get_json(silent=True) or {}
    limits = body.get("per_user_limits") if isinstance(body, dict) else None
    if not isinstance(limits, dict):
        limits_logger.warning("Limits update request invalid payload")
        return jsonify({"error": "Invalid payload", "code": "INVALID_ARGUMENT"}), 400

    client = _get_auth_client()
    if client is None:
        limits_logger.error("Limits update failed: client unavailable")
        return jsonify({"error": "Auth service client unavailable"}), 503

    try:
        upstream = client.update_limits(per_user_limits=limits)
    except ConnectionError:
        upstream_logger.error("Auth service limits request failed", exc_info=True)
        return jsonify({"error": "Auth service unreachable", "code": "AUTH_UPSTREAM_UNAVAILABLE"}), 502

    if upstream.ok and upstream.json:
        snapshot = upstream.json.get("per_user_limits")
        holder = current_app.config.get("rate_limit_holder")
        if holder and isinstance(snapshot, dict):
            try:
                holder.update(per_user_limits=snapshot)
                limits_logger.info(
                    "Applied per-user limits locally",
                    extra={"limit_count": len(snapshot)},
                )
            except Exception:
                limits_logger.warning("Failed to apply per-user limits locally", exc_info=True)
    else:
        limits_logger.warning(
            "Upstream limits update response not OK",
            extra={"status_code": getattr(upstream, "status_code", None)},
        )

    return _forward_response(upstream)


