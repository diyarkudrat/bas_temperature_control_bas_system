"""Authentication routes served by the standalone auth service.

All stateful collaborators (sessions, users, rate limit holder) are injected per
request by ``apps.auth_service.main`` so the module remains side-effect free and
safe under multi-process runtimes.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Mapping, Optional, Tuple

from flask import Blueprint, current_app, jsonify, request

from app_platform.security import ServiceTokenValidationError, verify_service_jwt
from logging_lib import get_logger as get_structured_logger

from apps.auth_service.http.schemas import (
    SchemaValidationError,
    parse_email_verified_event,
    parse_invite_create,
    parse_invite_accept,
    parse_org_provisioning,
)
from apps.auth_service.services import (
    DuplicateEventError,
    InviteConflictError,
    InviteExpiredError,
    InviteNotFoundError,
    InviteRateLimitError,
    InviteTokenError,
    ServiceConfigurationError,
    UnauthorizedRequestError,
    UpstreamServiceError,
)


auth_bp = Blueprint("auth_service", __name__)

logger = get_structured_logger("auth.routes")
token_logger = get_structured_logger("auth.routes.tokens")


def _scrub_identifier(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:12]


def _get_request_components() -> Tuple[Any, Any, Any, Any, Any]:
    """Best-effort helpers for pulling dependencies from the request context."""

    limiter = getattr(request, "rate_limiter", None)
    audit = getattr(request, "audit_logger", None)
    sessions = getattr(request, "session_manager", None)
    users = getattr(request, "user_manager", None)
    holder = getattr(request, "rate_limit_holder", None)
    return limiter, audit, sessions, users, holder


def _service_token_valid() -> bool:
    claims = _verify_service_token()
    if claims is None:
        return False
    request.service_token_claims = claims
    return True


def _verify_service_token() -> Optional[Mapping[str, Any]]:
    settings = getattr(request, "service_tokens", None)
    if settings is None:
        token_logger.error("Service token settings missing on request")
        return None

    auth_header = request.headers.get("Authorization", "")
    scheme, _, token_value = auth_header.partition(" ")
    if not token_value or scheme.lower() != "bearer":
        token_logger.warning("Missing bearer Authorization header for service request")
        return None
    token = token_value.strip()
    if not token:
        token_logger.warning("Bearer token present but empty for service request")
        return None

    try:
        claims = verify_service_jwt(
            token,
            settings.keyset,
            audience=settings.audience,
            issuer=settings.issuer,
            replay_cache=settings.replay_cache,
            required_scope=settings.required_scopes or None,
        )
    except ServiceTokenValidationError as exc:
        token_logger.warning(
            "Service token validation failed",
            extra={"error": str(exc)},
        )
        return None

    subject = claims.get("sub")
    if settings.allowed_subjects and subject not in settings.allowed_subjects:
        token_logger.warning(
            "Service token subject not allowed",
            extra={"subject": subject},
        )
        return None

    token_logger.info(
        "Service token accepted",
        extra={
            "subject": subject,
            "audience": claims.get("aud"),
            "kid": request.headers.get("X-Service-Token-Kid"),
            "scopes_present": bool(claims.get("scope")),
        },
    )

    return claims


@auth_bp.route("/auth/orgs/provision", methods=["POST"])
def provision_org_jwt() -> Any:
    service = getattr(request, "provisioning_service", None)
    if service is None or not getattr(service, "enabled", False):
        logger.warning("Provisioning request rejected: service unavailable")
        return jsonify({"error": "Provisioning unavailable", "code": "SERVICE_DISABLED"}), 503

    if not _service_token_valid():
        token_logger.warning("Provisioning request missing service token")
        return jsonify({"error": "Forbidden", "code": "FORBIDDEN"}), 403

    payload = request.get_json(silent=True) or {}
    try:
        schema = parse_org_provisioning(payload)
    except SchemaValidationError as exc:
        logger.info("Provisioning payload invalid", extra={"error": str(exc)})
        return jsonify({"error": "Invalid payload", "code": "INVALID_ARGUMENT", "details": str(exc)}), 400

    try:
        response = service.mint(
            schema,
            request_id=request.headers.get("X-Request-ID"),
            remote_addr=request.remote_addr,
        )
        body = response.to_dict()
        return jsonify(body), 200
    except ServiceConfigurationError as exc:
        logger.error("Provisioning service misconfigured", extra={"error": str(exc)})
        return jsonify({"error": "Provisioning unavailable", "code": "SERVICE_DISABLED"}), 503
    except Exception:  # noqa: BLE001
        logger.exception("Provisioning token issuance failed")
        return jsonify({"error": "Internal server error"}), 500


@auth_bp.route("/auth/invite", methods=["POST"])
def create_invite() -> Any:
    service = getattr(request, "invite_service", None)
    if service is None or not getattr(service, "enabled", False):
        logger.warning("Invite creation attempted while service disabled")
        return jsonify({"error": "Invite service unavailable", "code": "SERVICE_DISABLED"}), 503

    if not _service_token_valid():
        token_logger.warning("Invite creation missing service token")
        return jsonify({"error": "Forbidden", "code": "FORBIDDEN"}), 403

    payload = request.get_json(silent=True) or {}
    tenant_id = payload.get("tenantId") or payload.get("tenant_id")
    if not tenant_id or not isinstance(tenant_id, str) or not tenant_id.strip():
        return jsonify({"error": "tenant_id is required", "code": "INVALID_ARGUMENT"}), 400

    try:
        schema = parse_invite_create(payload, tenant_id=tenant_id)
    except SchemaValidationError as exc:
        logger.info("Invite payload invalid", extra={"error": str(exc), "tenant_id": tenant_id})
        return jsonify({"error": "Invalid payload", "code": "INVALID_ARGUMENT", "details": str(exc)}), 400

    try:
        invite = service.create_invite(schema)
    except InviteRateLimitError as exc:
        logger.info("Invite quota exceeded", extra={"tenant_id": tenant_id, "error": str(exc)})
        return jsonify({"error": "Rate limited", "code": "RATE_LIMITED"}), 429
    except InviteConflictError as exc:
        logger.info("Invite conflict detected", extra={"tenant_id": tenant_id, "error": str(exc)})
        return jsonify({"error": "Invite already exists", "code": "CONFLICT"}), 409
    except ServiceConfigurationError as exc:
        logger.error("Invite service misconfigured", extra={"tenant_id": tenant_id, "error": str(exc)})
        return jsonify({"error": "Invite service unavailable", "code": "SERVICE_DISABLED"}), 503
    except UpstreamServiceError as exc:
        logger.error("Invite upstream dependency error", extra={"tenant_id": tenant_id, "error": str(exc)})
        return jsonify({"error": "Upstream service error", "code": "UPSTREAM_ERROR"}), 502
    except Exception:  # noqa: BLE001
        logger.exception("Invite creation failed")
        return jsonify({"error": "Internal server error"}), 500

    body = {
        "invite_id": invite.invite_id,
        "status": invite.status.value,
    }
    if invite.token:
        body["token"] = invite.token
    return jsonify(body), 201


@auth_bp.route("/auth/accept-invite", methods=["POST"])
def accept_invite() -> Any:
    service = getattr(request, "invite_service", None)
    if service is None or not getattr(service, "enabled", False):
        logger.warning("Invite acceptance attempted while service disabled")
        return jsonify({"error": "Invite service unavailable", "code": "SERVICE_DISABLED"}), 503

    payload = request.get_json(silent=True) or {}
    try:
        schema = parse_invite_accept(payload)
    except SchemaValidationError as exc:
        logger.info("Invite acceptance payload invalid", extra={"error": str(exc)})
        return jsonify({"error": "Invalid payload", "code": "INVALID_ARGUMENT", "details": str(exc)}), 400

    try:
        result = service.accept_invite(schema)
    except InviteNotFoundError:
        return jsonify({"error": "Invite not found", "code": "INVITE_NOT_FOUND"}), 404
    except InviteExpiredError:
        return jsonify({"error": "Invite expired", "code": "INVITE_EXPIRED"}), 410
    except InviteTokenError:
        return jsonify({"error": "Invalid invite token", "code": "INVITE_TOKEN_INVALID"}), 401
    except ServiceConfigurationError as exc:
        logger.error("Invite acceptance misconfigured", extra={"error": str(exc)})
        return jsonify({"error": "Invite service unavailable", "code": "SERVICE_DISABLED"}), 503
    except UpstreamServiceError as exc:
        logger.error("Invite acceptance upstream failure", extra={"error": str(exc)})
        return jsonify({"error": "Upstream service error", "code": "UPSTREAM_ERROR"}), 502
    except Exception:  # noqa: BLE001
        logger.exception("Invite acceptance failed")
        return jsonify({"error": "Internal server error"}), 500

    body = {
        "status": result.status,
        "tenant_id": result.tenant_id,
        "member_id": result.member_id,
    }
    if result.token:
        body["token"] = result.token
    return jsonify(body), 200


@auth_bp.route("/auth/events/email-verified", methods=["POST"])
def handle_email_verified_event() -> Any:
    service = getattr(request, "verification_service", None)
    if service is None:
        logger.warning("Verification event received but service disabled")
        return jsonify({"error": "Verification handling disabled", "code": "SERVICE_DISABLED"}), 503

    raw_body = request.get_data(cache=True, as_text=False) or b""
    try:
        service.validate_signature(request.headers, raw_body)
    except ServiceConfigurationError as exc:
        logger.error("Verification signature validation misconfigured", extra={"error": str(exc)})
        return jsonify({"error": "Verification unavailable", "code": "SERVICE_DISABLED"}), 503
    except UnauthorizedRequestError as exc:
        logger.info("Verification signature rejected", extra={"error": str(exc)})
        return jsonify({"error": "Forbidden", "code": "FORBIDDEN"}), 403

    payload = request.get_json(silent=True) or {}
    try:
        event = parse_email_verified_event(payload)
    except SchemaValidationError as exc:
        logger.info("Verification payload invalid", extra={"error": str(exc)})
        return jsonify({"error": "Invalid payload", "code": "INVALID_ARGUMENT", "details": str(exc)}), 400

    try:
        service.process_email_verified(event)
    except DuplicateEventError:
        logger.info("Duplicate verification event ignored", extra={"event_id": event.event_id})
        return "", 202
    except ServiceConfigurationError as exc:
        logger.error("Verification service misconfigured", extra={"error": str(exc)})
        return jsonify({"error": "Verification unavailable", "code": "SERVICE_DISABLED"}), 503
    except UpstreamServiceError as exc:
        logger.error("Verification forwarding failed", extra={"error": str(exc), "event_id": event.event_id})
        return jsonify({"error": "Upstream service error", "code": "UPSTREAM_ERROR"}), 502
    except Exception:  # noqa: BLE001
        logger.exception("Verification event processing failed")
        return jsonify({"error": "Internal server error"}), 500

    return "", 204


@auth_bp.route("/auth/login", methods=["POST"])
def auth_login():
    cfg = getattr(request, "auth_config", None)
    if not cfg or not getattr(cfg, "auth_enabled", False):
        logger.warning(
            "Login attempt rejected: auth disabled",
            extra={"config_present": cfg is not None},
        )
        return jsonify({"error": "Authentication disabled"}), 503

    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    if not username or not password:
        logger.warning(
            "Login attempt missing required fields",
            extra={"username_present": bool(username)},
        )
        return jsonify({"error": "Missing required fields", "code": "MISSING_FIELDS"}), 400

    username_hash = _scrub_identifier(username)
    remote_hash = _scrub_identifier(request.remote_addr)
    logger.info(
        "Login attempt received",
        extra={"username_hash": username_hash, "remote_hash": remote_hash},
    )

    limiter, audit, sessions, users, _ = _get_request_components()
    if sessions is None or users is None:
        logger.error(
            "Auth runtime not fully initialized",
            extra={"sessions_missing": sessions is None, "users_missing": users is None},
        )
        return jsonify({"error": "Authentication system unavailable"}), 500

    try:
        allowed, message = limiter.is_allowed(request.remote_addr, username) if limiter else (True, "Allowed")
        if not allowed:
            logger.info(
                "Login rate limited",
                extra={"username_hash": username_hash, "remote_hash": remote_hash, "message": message},
            )
            if audit:
                audit.log_auth_failure(username, request.remote_addr, "RATE_LIMITED")
            return jsonify({"error": message, "code": "RATE_LIMITED"}), 429

        user = users.authenticate_user(username, password)
        if not user:
            if limiter:
                limiter.record_attempt(request.remote_addr, username)
            logger.info(
                "Login failed: invalid credentials",
                extra={"username_hash": username_hash, "remote_hash": remote_hash},
            )
            if audit:
                audit.log_auth_failure(username, request.remote_addr, "INVALID_CREDENTIALS")
            return jsonify({"error": "Invalid credentials", "code": "AUTH_FAILED"}), 401

        if user.is_locked():
            logger.info(
                "Login failed: account locked",
                extra={"username_hash": username_hash},
            )
            if audit:
                audit.log_auth_failure(username, request.remote_addr, "ACCOUNT_LOCKED")
            return jsonify({"error": "Account locked", "code": "USER_LOCKED"}), 423

        session = sessions.create_session(username, user.role, request)
        users.update_last_login(username)
        if limiter:
            limiter.clear_attempts(request.remote_addr, username)
        if audit:
            audit.log_auth_success(username, request.remote_addr, session.session_id)

        logger.info(
            "Login succeeded",
            extra={
                "username_hash": username_hash,
                "role": user.role,
                "tenant_present": bool(getattr(session, "tenant_id", None)),
            },
        )

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
        logger.exception("Auth login failed")
        return jsonify({"error": "Internal server error"}), 500


@auth_bp.route("/auth/logout", methods=["POST"])
def auth_logout():
    _, audit, sessions, _, _ = _get_request_components()
    if sessions is None:
        logger.error("Session manager missing in logout handler")
        return jsonify({"error": "Authentication system unavailable"}), 500

    try:
        sid = request.cookies.get("bas_session_id")
        if not sid:
            payload = request.get_json(silent=True) or {}
            sid = payload.get("session_id")

        sid_hash = _scrub_identifier(sid) if sid else None
        logger.info(
            "Logout requested",
            extra={"session_present": bool(sid)},
        )

        if sid:
            sessions.invalidate_session(sid)
            if audit:
                audit.log_session_destruction(sid)

        resp = jsonify({"status": "success", "message": "Logged out successfully"})
        resp.set_cookie("bas_session_id", "", max_age=0, httponly=True, secure=True, samesite="Strict")
        logger.info(
            "Logout completed",
            extra={"session_hash": sid_hash},
        )
        return resp
    except Exception as exc:  # noqa: BLE001
        logger.exception("Auth logout failed")
        return jsonify({"error": "Internal server error"}), 500


@auth_bp.route("/auth/status", methods=["GET"])
def auth_status():
    _, _, sessions, _, _ = _get_request_components()
    if sessions is None:
        logger.error("Session manager missing in status handler")
        return jsonify({"error": "Authentication system unavailable"}), 500

    sid = request.cookies.get("bas_session_id") or request.headers.get("X-Session-ID")
    if not sid:
        logger.info("Status check missing session identifier")
        return jsonify({"error": "No session provided", "code": "NO_SESSION"}), 400

    try:
        session = sessions.validate_session(sid, request)
        if not session:
            logger.info(
                "Status check invalid session",
                extra={"session_hash": _scrub_identifier(sid)},
            )
            return jsonify({"error": "Invalid or expired session", "code": "SESSION_INVALID"}), 401

        logger.info(
            "Status check succeeded",
            extra={
                "username_hash": _scrub_identifier(getattr(session, "username", None)),
                "role": getattr(session, "role", None),
                "tenant_present": bool(getattr(session, "tenant_id", None)),
            },
        )

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
        logger.exception("Auth status failed")
        return jsonify({"error": "Internal server error"}), 500


@auth_bp.route("/auth/limits", methods=["POST"])
def update_per_user_limits():
    _, _, _, _, holder = _get_request_components()
    if holder is None:
        holder = current_app.config.get("rate_limit_holder")
    if holder is None:
        logger.error("Rate limit holder unavailable")
        return jsonify({"error": "Rate limit holder unavailable"}), 500

    if not _service_token_valid():
        token_logger.warning("Service token missing or invalid for limits update")
        return jsonify({"error": "Forbidden", "code": "FORBIDDEN"}), 403

    try:
        body = request.get_json(silent=True) or {}
        limits = body.get("per_user_limits") if isinstance(body, dict) else None
        if not isinstance(limits, dict):
            logger.warning("Limits update rejected: invalid payload structure")
            return jsonify({"error": "Invalid payload", "code": "INVALID_ARGUMENT"}), 400

        claims = getattr(request, "service_token_claims", {}) or {}
        subject = claims.get("sub")
        logger.info(
            "Received per-user limits update",
            extra={"subject": subject, "limit_count": len(limits)},
        )

        snap = holder.update(per_user_limits=limits)
        snapshot = snap.get_per_user_limits_snapshot()
        logger.info(
            "Per-user limits updated",
            extra={"subject": subject, "limit_count": len(snapshot)},
        )
        return jsonify({"per_user_limits": snapshot}), 200
    except ValueError as exc:
        logger.warning(
            "Limits update rejected: value error",
            extra={"error": str(exc)},
        )
        return jsonify({"error": str(exc), "code": "INVALID_ARGUMENT"}), 400
    except Exception as exc:  # noqa: BLE001
        logger.exception("Updating per-user limits failed")
        return jsonify({"error": "Internal server error"}), 500

