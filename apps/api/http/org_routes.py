"""Organization onboarding HTTP endpoints."""

from __future__ import annotations

import base64
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, List, Mapping, MutableMapping, Optional, Tuple

from flask import Blueprint, Response, current_app, jsonify, request

from logging_lib import get_logger as get_structured_logger

from adapters.db.firestore.base import FirestoreError, QueryOptions
from adapters.db.firestore.models import OutboxEvent
from adapters.db.firestore.service_factory import FirestoreServiceFactory
from app_platform.contracts import (
    PROVISIONING_HEADERS,
    PROVISIONING_JWT,
    DeviceLifecycle,
    MemberRole,
    TenantStatus,
)
from app_platform.security import (
    ReplayCache,
    ServiceTokenValidationError,
    load_replay_cache_from_env,
    load_service_keyset_from_env,
    verify_service_jwt,
)
from app_platform.security.captcha import (
    CaptchaConfig,
    CaptchaVerificationError,
    CaptchaVerifier,
)
from apps.api.http.middleware import (
    enforce_idempotency,
    enforce_tenant_isolation,
    require_auth,
    require_device_access,
)
from apps.api.http.middleware.limiters import SlidingWindowLimiter
from apps.api.http.schemas import SchemaValidationError
from apps.api.services.device_credentials import DeviceCredentialRecord
from apps.api.http.schemas.org import (
    DeviceRegistrationRequest,
    EmailVerifiedEvent,
    InviteCreateRequest,
    OrgSignupRequest,
    OrgSignupResponse,
    parse_email_verified_event,
    parse_invite_create,
    parse_device_registration,
    parse_org_signup,
    DeviceRegistrationResponse,
)


org_bp = Blueprint("orgs", __name__)

logger = get_structured_logger("api.http.orgs")
captcha_logger = get_structured_logger("api.http.orgs.captcha")
idempotency_logger = get_structured_logger("api.http.orgs.idempotency")
events_logger = get_structured_logger("api.http.orgs.events")
invite_logger = get_structured_logger("api.http.orgs.invite")
device_logger = get_structured_logger("api.http.orgs.device")


class OrgSignupError(Exception):
    """Base error capturing API-safe message and status code."""

    def __init__(self, message: str, *, code: str, status: int) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


class TenantConflictError(OrgSignupError):
    """Raised when a tenant already exists for the requested identifier."""

    def __init__(self, message: str = "Tenant already exists", code: str = "TENANT_CONFLICT") -> None:
        super().__init__(message, code=code, status=409)


class ProvisioningTokenError(OrgSignupError):
    """Raised when provisioning JWT validation fails."""

    def __init__(self, message: str, code: str = "PROVISIONING_JWT_INVALID", status: int = 401) -> None:
        super().__init__(message, code=code, status=status)


class RequestTokenError(OrgSignupError):
    """Raised when a signed request token fails validation."""

    def __init__(self, message: str, code: str = "REQUEST_JWT_INVALID", status: int = 401) -> None:
        super().__init__(message, code=code, status=status)


class InviteConflictError(OrgSignupError):
    """Raised when an invite already exists for the given tenant/email."""

    def __init__(self, message: str = "Invite already exists", code: str = "INVITE_CONFLICT", status: int = 409) -> None:
        super().__init__(message, code=code, status=status)


class DeviceOperationError(OrgSignupError):
    """Base error for device lifecycle operations."""


class DeviceConflictError(DeviceOperationError):
    """Raised when a device already exists."""

    def __init__(self, message: str = "Device already exists", code: str = "DEVICE_CONFLICT", status: int = 409) -> None:
        super().__init__(message, code=code, status=status)


class DeviceQuotaExceededError(DeviceOperationError):
    """Raised when tenant device quota reached."""

    def __init__(self, message: str = "Device quota exceeded", code: str = "DEVICE_QUOTA_EXCEEDED", status: int = 409) -> None:
        super().__init__(message, code=code, status=status)


class DeviceNotFoundError(DeviceOperationError):
    """Raised when a device is missing."""

    def __init__(self, message: str = "Device not found", code: str = "DEVICE_NOT_FOUND", status: int = 404) -> None:
        super().__init__(message, code=code, status=status)


@dataclass(slots=True)
class DurableReservation:
    """Durable reservation for idempotency."""

    status: str
    entry: Optional[Any]


@dataclass(slots=True)
class EmailActivationResult:
    """Email activation result."""

    status: str
    tenant_id: str
    member_id: Optional[str] = None
    tenant_name: Optional[str] = None


@org_bp.route("/orgs/signup", methods=["POST"])
@enforce_idempotency()
def org_signup() -> Response:
    """Handle organization signup requests."""

    if not _org_signup_enabled():
        logger.info("Org signup called while feature disabled")

        return _json_error("Organization signup unavailable", "ORG_SIGNUP_DISABLED", 404)

    firestore_factory = _resolve_firestore_factory()
    if firestore_factory is None:
        logger.error("Org signup attempted without Firestore factory configured")

        return _json_error("Organization signup unavailable", "SERVICE_UNAVAILABLE", 503)

    payload = request.get_json(silent=True) or {}
    try:
        schema = parse_org_signup(payload)
    except SchemaValidationError as exc:
        logger.info("Org signup payload invalid", extra={"error": str(exc)})

        return _json_error("Invalid payload", "INVALID_ARGUMENT", 400, details=str(exc))

    config = _org_flows_config()

    try:
        _verify_captcha_if_required(schema, config)
    except CaptchaVerificationError as exc:
        captcha_logger.warning("CAPTCHA verification failed", extra={"error": str(exc)})

        return _json_error("Captcha verification failed", "CAPTCHA_FAILED", 400)

    try:
        provisioning_token = _resolve_provisioning_token(schema)
    except OrgSignupError as exc:
        return _error_response(exc)

    try:
        claims = _verify_provisioning_token(provisioning_token)
    except ProvisioningTokenError as exc:
        logger.warning("Provisioning token invalid", extra={"error": exc.message})
        return _error_response(exc)

    try:
        _validate_claims_against_request(claims, schema)
    except OrgSignupError as exc:
        logger.warning("Provisioning token mismatch", extra={"error": exc.message})
        return _error_response(exc)

    hashed_key, payload_hash = _compute_idempotency_keys(schema, payload)

    reservation = _reserve_durable_idempotency(
        firestore_factory,
        hashed_key=hashed_key,
        payload_hash=payload_hash,
    )

    if reservation.status == "completed" and reservation.entry is not None:
        idempotency_logger.info("Replay fulfilled from durable store", extra={"key": hashed_key})

        return _response_from_durable_entry(reservation.entry)

    if reservation.status == "in_progress":
        idempotency_logger.info("Durable idempotency indicates in-progress request", extra={"key": hashed_key})
        return _json_error("Request already in progress", "REQUEST_IN_PROGRESS", 409)

    try:
        signup_response = _execute_signup_transaction(
            firestore_factory,
            schema,
            claims,
            config,
            payload_hash=payload_hash,
        )
    except TenantConflictError as exc:
        _release_durable_idempotency(firestore_factory, hashed_key)

        return _error_response(exc)
    except Exception as exc:  # noqa: BLE001
        _release_durable_idempotency(firestore_factory, hashed_key)
        logger.exception("Org signup transaction failed")

        return _json_error("Internal server error", "INTERNAL_ERROR", 500)

    response = jsonify(signup_response.to_dict())
    response.status_code = 202
    response.headers.setdefault("Idempotency-Key", request.headers.get(PROVISIONING_HEADERS.idempotency_key_header, ""))

    try:
        _record_durable_response(firestore_factory, hashed_key, response)
    except Exception as exc:  # noqa: BLE001 - best effort persistence
        idempotency_logger.warning("Failed to persist durable idempotency response", extra={"error": str(exc)})

    return response


@org_bp.route("/auth/events/email-verified", methods=["POST"])
def email_verified_event() -> Response:
    """Accept Auth0 email verification events forwarded by the auth-service."""

    if not _org_signup_enabled():
        return _json_error("Resource not found", "NOT_FOUND", 404)

    firestore_factory = _resolve_firestore_factory()
    if firestore_factory is None:
        events_logger.warning("Email verified event received without Firestore availability")
        return _json_error("Event processing unavailable", "SERVICE_UNAVAILABLE", 503)

    try:
        claims = _verify_service_event_token()
    except OrgSignupError as exc:
        return _error_response(exc)

    payload = request.get_json(silent=True) or {}
    try:
        event = parse_email_verified_event(payload)
    except SchemaValidationError as exc:
        events_logger.info("Email verified payload invalid", extra={"error": str(exc)})

        return _json_error("Invalid payload", "INVALID_ARGUMENT", 400, details=str(exc))

    cache = _email_event_replay_cache()
    replay_key = f"email-verified:{event.event_id}:{event.auth0_user_id}"

    if cache is not None and not cache.check_and_store(replay_key, expires_at=event.verified_at + 600):
        events_logger.info("Duplicate email verified event suppressed", extra={"event_id": event.event_id})

        return Response(status=202)

    try:
        outcome = _activate_verified_admin(firestore_factory, event, claims)
    except FirestoreError as exc:
        events_logger.error(
            "Failed to activate tenant on verification event",
            extra={"event_id": event.event_id, "error": str(exc)},
        )

        return _json_error("Event processing unavailable", "SERVICE_UNAVAILABLE", 503)
    except Exception as exc:  # noqa: BLE001
        events_logger.exception("Unexpected failure during tenant activation")

        return _json_error("Internal server error", "INTERNAL_ERROR", 500)

    if outcome.status == "tenant_missing":
        events_logger.warning(
            "Verification event received for unknown tenant",
            extra={"event_id": event.event_id, "tenant_id": event.tenant_id},
        )

        return Response(status=202)

    if outcome.status == "member_missing":
        events_logger.warning(
            "Verification event missing pending admin",
            extra={"event_id": event.event_id, "tenant_id": event.tenant_id},
        )

        return Response(status=202)

    if outcome.status == "noop":
        events_logger.info(
            "Verification event already applied",
            extra={
                "event_id": event.event_id,
                "tenant_id": event.tenant_id,
                "member_id": outcome.member_id,
            },
        )

        return Response(status=204)

    events_logger.info(
        "Tenant admin activated",
        extra={
            "event_id": event.event_id,
            "tenant_id": event.tenant_id,
            "member_id": outcome.member_id,
            "tenant_name": outcome.tenant_name,
        },
    )

    return Response(status=204)


@org_bp.route("/tenants/<tenant_id>/users/invite", methods=["POST"])
@require_auth(required_role="admin", require_tenant=True)
@enforce_tenant_isolation
def create_tenant_invite(tenant_id: str) -> Response:
    """Create a new tenant invite for the given email address."""

    if not _org_signup_enabled():
        return _json_error("Resource not found", "NOT_FOUND", 404)

    firestore_factory = _resolve_firestore_factory()
    if firestore_factory is None:
        invite_logger.error("Invite attempted without Firestore availability", extra={"tenant_id": tenant_id})
        return _json_error("Invite service unavailable", "SERVICE_UNAVAILABLE", 503)

    try:
        request_claims = _verify_request_jwt(tenant_id)
    except OrgSignupError as exc:
        return _error_response(exc)

    payload = request.get_json(silent=True) or {}
    try:
        schema = parse_invite_create(payload, tenant_id=tenant_id)
    except SchemaValidationError as exc:
        invite_logger.info("Invite payload invalid", extra={"error": str(exc), "tenant_id": tenant_id})
        return _json_error("Invalid payload", "INVALID_ARGUMENT", 400, details=str(exc))

    config = _org_flows_config()
    quota = int(getattr(config, "invite_quota_per_tenant", 20) or 20)
    window_minutes = int(getattr(config, "invite_quota_window_minutes", 60) or 60)

    if not _invite_rate_limiter_allow(tenant_id, quota, window_minutes * 60):
        invite_logger.info("Invite rate limited", extra={"tenant_id": tenant_id, "quota": quota})
        return _json_error("Rate limited", "INVITE_RATE_LIMITED", 429)

    client = getattr(request, "auth_service_client", None)
    if client is None:
        invite_logger.error("Auth service client unavailable for invite", extra={"tenant_id": tenant_id})
        return _json_error("Invite service unavailable", "SERVICE_UNAVAILABLE", 503)

    actor_email, actor_user_id = _resolve_invite_actor()
    member_id = _derive_invited_member_id(schema.email)
    now_ms = int(time.time() * 1000)

    metadata = dict[str, Any](schema.metadata or {})
    metadata.setdefault("memberId", member_id)
    sanitized_claims = _sanitize_request_claims(request_claims)
    if sanitized_claims:
        metadata["requestClaims"] = sanitized_claims
    if actor_user_id:
        metadata.setdefault("invitedByUserId", actor_user_id)
    if actor_email:
        metadata.setdefault("invitedByEmail", actor_email)

    auth_payload: MutableMapping[str, Any] = {
        "tenantId": tenant_id,
        "email": schema.email,
        "role": schema.role.value,
        "sendEmail": schema.send_email,
        "metadata": metadata,
    }

    inviter_identity = schema.invited_by or actor_email or actor_user_id
    if inviter_identity:
        auth_payload["invitedBy"] = inviter_identity
    if schema.expires_in_hours is not None:
        auth_payload["expiresInHours"] = schema.expires_in_hours

    try:
        auth_response = client.create_invite(tenant_id=tenant_id, payload=auth_payload)
    except ConnectionError:
        invite_logger.error("Auth service invite request failed", extra={"tenant_id": tenant_id}, exc_info=True)
        return _json_error("Invite service unavailable", "AUTH_SERVICE_UNAVAILABLE", 502)

    if not auth_response.ok:
        body = auth_response.json or {}
        error_message = str(body.get("error") or "Invite creation failed")
        error_code = str(body.get("code") or "INVITE_FAILED")
        status_code = auth_response.status_code or 500

        invite_logger.info(
            "Invite rejected by auth service",
            extra={
                "tenant_id": tenant_id,
                "status": status_code,
                "code": error_code,
            },
        )

        if status_code == 409:
            return _json_error(error_message, error_code, 409)
        if status_code == 429:
            return _json_error(error_message, error_code, 429)
        if status_code in {502, 503}:
            return _json_error(error_message, error_code, status_code)
        if 400 <= status_code < 500:
            return _json_error(error_message, error_code, status_code)

        return _json_error("Invite creation failed", "INVITE_FAILED", 502)

    invite_payload = auth_response.json or {}
    invite_id = invite_payload.get("invite_id") or invite_payload.get("inviteId")
    invite_token = invite_payload.get("token")

    if not invite_id:
        invite_logger.error("Invite response missing invite_id", extra={"tenant_id": tenant_id})
        return _json_error("Invite service response invalid", "INVITE_RESPONSE_INVALID", 502)

    try:
        status = _finalize_invite_records(
            firestore_factory,
            tenant_id=tenant_id,
            member_id=member_id,
            invite_id=str(invite_id),
            invite_token=invite_token,
            schema=schema,
            actor_email=actor_email,
            actor_user_id=actor_user_id,
            request_claims=sanitized_claims,
            now_ms=now_ms,
        )
    except InviteConflictError as exc:
        invite_logger.warning(
            "Invite finalization conflict",
            extra={"tenant_id": tenant_id, "invite_id": invite_id},
        )
        return _error_response(exc)
    except RequestTokenError as exc:
        invite_logger.error(
            "Invite finalization failed: tenant missing",
            extra={"tenant_id": tenant_id, "invite_id": invite_id},
        )
        return _error_response(exc)
    except FirestoreError as exc:
        invite_logger.error(
            "Invite finalization Firestore error",
            extra={"tenant_id": tenant_id, "invite_id": invite_id, "error": str(exc)},
        )
        return _json_error("Invite persistence failed", "SERVICE_UNAVAILABLE", 503)
    except Exception:  # noqa: BLE001
        invite_logger.exception(
            "Unexpected error finalizing invite",
            extra={"tenant_id": tenant_id, "invite_id": invite_id},
        )
        return _json_error("Internal server error", "INTERNAL_ERROR", 500)

    invite_logger.info(
        "Invite created",
        extra={
            "tenant_id": tenant_id,
            "invite_id": invite_id,
            "email_hash": hashlib_sha256(schema.email.lower())[:12],
            "status": status,
        },
    )

    response_body: MutableMapping[str, Any] = {
        "inviteId": invite_id,
        "status": "pending",
    }
    if invite_token:
        response_body["token"] = invite_token

    response = jsonify(response_body)
    response.status_code = 202
    
    return response


# ---------------------------------------------------------------------------
# Device lifecycle routes
# ---------------------------------------------------------------------------


@org_bp.route("/tenants/<tenant_id>/devices", methods=["POST"])
@enforce_idempotency()
@require_auth(required_role="operator", require_tenant=True)
@enforce_tenant_isolation
@require_device_access
def register_device(tenant_id: str) -> Response:
    if not _devices_feature_enabled():
        return _json_error("Resource not found", "NOT_FOUND", 404)

    firestore_factory = _resolve_firestore_factory()
    if firestore_factory is None:
        device_logger.error("Device registration attempted without Firestore", extra={"tenant_id": tenant_id})
        return _json_error("Device service unavailable", "SERVICE_UNAVAILABLE", 503)

    credential_service = _resolve_device_credential_service()
    if credential_service is None:
        device_logger.error("Credential service unavailable", extra={"tenant_id": tenant_id})
        return _json_error("Device credential service unavailable", "CREDENTIAL_SERVICE_UNAVAILABLE", 503)

    try:
        request_claims = _verify_request_jwt(tenant_id)
    except OrgSignupError as exc:
        return _error_response(exc)

    payload = request.get_json(silent=True) or {}
    try:
        schema = parse_device_registration(payload, tenant_id=tenant_id)
    except SchemaValidationError as exc:
        device_logger.info("Device registration payload invalid", extra={"tenant_id": tenant_id, "error": str(exc)})
        return _json_error("Invalid payload", "INVALID_ARGUMENT", 400, details=str(exc))

    if not schema.device_id:
        return _json_error("Device ID required", "MISSING_DEVICE_ID", 400)

    actor_email, actor_user_id = _resolve_device_actor()
    sanitized_claims = _sanitize_request_claims(request_claims)
    now_ms = int(time.time() * 1000)

    credential_record = credential_service.issue_credentials(
        tenant_id=tenant_id,
        device_id=schema.device_id,
        metadata={"hardwareId": schema.hardware_id},
    )

    try:
        response_schema = _create_device_record(
            firestore_factory,
            schema,
            credential_record=credential_record,
            actor_email=actor_email,
            actor_user_id=actor_user_id,
            request_claims=sanitized_claims,
            now_ms=now_ms,
        )
    except DeviceOperationError as exc:
        return _error_response(exc)
    except FirestoreError as exc:
        device_logger.error(
            "Device registration Firestore error",
            extra={"tenant_id": tenant_id, "error": str(exc)},
        )
        return _json_error("Device registration failed", "SERVICE_UNAVAILABLE", 503)
    except Exception:  # noqa: BLE001
        device_logger.exception("Unexpected error during device registration", extra={"tenant_id": tenant_id})
        return _json_error("Internal server error", "INTERNAL_ERROR", 500)

    device_logger.info(
        "Device registered",
        extra={
            "tenant_id": tenant_id,
            "device_id": schema.device_id,
            "credential_ref": credential_record.credential_reference,
        },
    )

    response = jsonify(response_schema.to_dict())
    response.status_code = 201

    return response


@org_bp.route("/tenants/<tenant_id>/devices", methods=["GET"])
@require_auth(required_role="read-only", require_tenant=True)
@enforce_tenant_isolation
def list_tenant_devices(tenant_id: str) -> Response:
    """List the devices for a tenant."""

    if not _devices_feature_enabled():
        return _json_error("Resource not found", "NOT_FOUND", 404)

    firestore_factory = _resolve_firestore_factory()
    if firestore_factory is None:
        return _json_error("Device service unavailable", "SERVICE_UNAVAILABLE", 503)

    try:
        repository = firestore_factory.get_devices_service()
    except Exception as exc:  # noqa: BLE001
        device_logger.error("Failed to resolve device repository", extra={"error": str(exc)})
        return _json_error("Device service unavailable", "SERVICE_UNAVAILABLE", 503)

    limit = _coerce_int(request.args.get("pageSize"), default=50, minimum=1, maximum=200)
    cursor = request.args.get("cursor")
    status_filter = request.args.get("status")

    options = QueryOptions(limit=limit, offset=cursor)
    filters: MutableMapping[str, Any] = {"tenant_id": tenant_id}

    if status_filter:
        filters["status"] = status_filter.lower()
    options.filters = dict(filters)

    try:
        result = repository.list_for_tenant(tenant_id, options)
    except Exception:  # noqa: BLE001
        device_logger.exception("Device listing failed", extra={"tenant_id": tenant_id})
        return _json_error("Device listing failed", "SERVICE_UNAVAILABLE", 503)

    if not result.success or result.data is None:
        code = result.error_code or "DEVICE_LIST_FAILED"
        msg = result.error or "Unable to list devices"
        return _json_error(msg, code, 503)

    payload = {
        "items": [_serialize_device(device) for device in result.data.items],
        "hasMore": bool(result.data.has_more),
        "nextCursor": result.data.next_offset,
    }

    return jsonify(payload)


@org_bp.route("/tenants/<tenant_id>/devices/<device_id>", methods=["DELETE"])
@require_auth(required_role="operator", require_tenant=True)
@enforce_tenant_isolation
@require_device_access
def delete_tenant_device(tenant_id: str, device_id: str) -> Response:
    """Delete a device for a tenant."""

    if not _devices_feature_enabled():
        return _json_error("Resource not found", "NOT_FOUND", 404)

    firestore_factory = _resolve_firestore_factory()
    if firestore_factory is None:
        return _json_error("Device service unavailable", "SERVICE_UNAVAILABLE", 503)

    try:
        request_claims = _verify_request_jwt(tenant_id)
    except OrgSignupError as exc:
        return _error_response(exc)

    sanitized_claims = _sanitize_request_claims(request_claims)
    actor_email, actor_user_id = _resolve_device_actor()
    now_ms = int(time.time() * 1000)

    try:
        outcome = _soft_delete_device_record(
            firestore_factory,
            tenant_id=tenant_id,
            device_id=device_id,
            actor_email=actor_email,
            actor_user_id=actor_user_id,
            request_claims=sanitized_claims,
            now_ms=now_ms,
        )
    except DeviceOperationError as exc:
        return _error_response(exc)
    except FirestoreError as exc:
        device_logger.error("Device delete Firestore error", extra={"tenant_id": tenant_id, "error": str(exc)})
        return _json_error("Device deletion failed", "SERVICE_UNAVAILABLE", 503)
    except Exception:  # noqa: BLE001
        device_logger.exception("Unexpected error during device deletion", extra={"tenant_id": tenant_id})
        return _json_error("Internal server error", "INTERNAL_ERROR", 500)

    response = jsonify(outcome)
    response.status_code = 202 if outcome.get("status") == "deleted" else 204

    return response


# ---------------------------------------------------------------------------
# Helper routines
# ---------------------------------------------------------------------------


def _org_signup_enabled() -> bool:
    """Check if the org signup is enabled."""

    flag = current_app.config.get("org_signup_v2_enabled")

    if flag is None:
        server = getattr(request, "server_config", None)

        try:
            return bool(getattr(getattr(server, "org_flows", None), "org_signup_v2_enabled", False))
        except Exception:
            return False

    return bool(flag)


def _devices_feature_enabled() -> bool:
    """Check if the devices feature is enabled."""

    if not _org_signup_enabled():
        return False

    flag = current_app.config.get("device_rbac_enforcement")

    if flag is None:
        server = getattr(request, "server_config", None)

        try:
            return bool(getattr(getattr(server, "org_flows", None), "device_rbac_enforcement", False))
        except Exception:
            return False

    return bool(flag)


def _org_flows_config():
    """Resolve the org flows config."""

    config = current_app.config.get("org_flows_config")

    if config is not None:
        return config

    server = getattr(request, "server_config", None)

    return getattr(server, "org_flows", None)


def _resolve_firestore_factory() -> Optional[FirestoreServiceFactory]:
    """Resolve the firestore factory."""

    direct = current_app.config.get("firestore_factory")

    if direct:
        return direct

    return getattr(request, "firestore_factory", None)


def _resolve_device_credential_service():
    """Resolve the device credential service."""

    service = current_app.config.get("device_credential_service")

    if service is not None:
        return service

    return getattr(request, "device_credential_service", None)


def _verify_captcha_if_required(schema: OrgSignupRequest, config) -> None:
    """Verify the captcha if required."""

    provider = getattr(config, "captcha_provider", None) if config else None
    secret_handle = getattr(config, "captcha_secret_handle", None) if config else None

    if not provider:
        return

    verifier = _captcha_verifier(provider, secret_handle, getattr(config, "captcha_min_score", 0.5), getattr(config, "captcha_site_key", None))

    if verifier is None:
        return

    verifier.verify(schema.captcha_token, remote_addr=request.remote_addr)


def _captcha_verifier(provider: str, secret_handle: Optional[str], min_score: float, site_key: Optional[str]) -> Optional[CaptchaVerifier]:
    """Verify the captcha."""

    if not secret_handle:
        captcha_logger.warning("Captcha provider configured without secret handle; skipping verification")
        return None

    cache_key = "_org_signup_captcha_verifier"
    cached = current_app.config.get(cache_key)

    if isinstance(cached, CaptchaVerifier):
        return cached

    try:
        config = CaptchaConfig(provider=provider, secret_handle=secret_handle, min_score=min_score, site_key=site_key)
        verifier = CaptchaVerifier(config)
    except CaptchaVerificationError as exc:
        captcha_logger.error("Captcha verifier initialization failed", extra={"error": str(exc)})
        return None

    current_app.config[cache_key] = verifier

    return verifier


def _resolve_provisioning_token(schema: OrgSignupRequest) -> str:
    """Resolve the provisioning token."""

    header_token = request.headers.get(PROVISIONING_HEADERS.provisioning_jwt_header)
    token = header_token or schema.provisioning_jwt

    if not token or not token.strip():
        raise ProvisioningTokenError("Provisioning token required", code="PROVISIONING_JWT_MISSING", status=401)

    return token.strip()


def _verify_provisioning_token(token: str) -> Mapping[str, Any]:
    prefix = os.getenv("ORG_SIGNUP_JWT_PREFIX", "ORG_SIGNUP_JWT") or "ORG_SIGNUP_JWT"
    keyset_cache_key = "_org_signup_provisioning_keyset"
    replay_cache_key = "_org_signup_provisioning_replay_cache"

    keyset = current_app.config.get(keyset_cache_key)

    if keyset is None:
        try:
            keyset = load_service_keyset_from_env(prefix=prefix)
        except Exception as exc:  # noqa: BLE001
            raise ProvisioningTokenError("Provisioning verifier not configured", status=503) from exc

        current_app.config[keyset_cache_key] = keyset

    replay_cache = current_app.config.get(replay_cache_key)
    if replay_cache is None:
        replay_cache = load_replay_cache_from_env(prefix=prefix, namespace="org-signup")
        current_app.config[replay_cache_key] = replay_cache

    try:
        claims = verify_service_jwt(
            token,
            keyset,
            audience=PROVISIONING_JWT.audience,
            issuer=PROVISIONING_JWT.issuer,
            replay_cache=replay_cache,
            leeway_seconds=5,
        )
    except ServiceTokenValidationError as exc:
        raise ProvisioningTokenError(str(exc)) from exc

    subject = claims.get("sub")
    if subject != PROVISIONING_JWT.subject:
        raise ProvisioningTokenError("Provisioning token subject mismatch", code="PROVISIONING_JWT_FORBIDDEN", status=403)

    return claims


def _validate_claims_against_request(claims: Mapping[str, Any], schema: OrgSignupRequest) -> None:
    """Validate the claims against the request."""

    tenant_claim = claims.get(PROVISIONING_JWT.tenant_claim) or {}
    if not isinstance(tenant_claim, Mapping):
        raise ProvisioningTokenError("Provisioning token missing tenant claim", status=403)

    token_email = str(tenant_claim.get("admin_email") or "").lower()
    if token_email and token_email != schema.admin_email.lower():
        raise ProvisioningTokenError("Provisioning token email mismatch", code="PROVISIONING_JWT_EMAIL_MISMATCH", status=403)

    token_name = str(tenant_claim.get("tenant_name") or "")
    if token_name and token_name.strip().lower() != schema.organization_name.strip().lower():
        raise ProvisioningTokenError("Provisioning token organization mismatch", code="PROVISIONING_JWT_TENANT_MISMATCH", status=403)


def _compute_idempotency_keys(schema: OrgSignupRequest, payload: Mapping[str, Any]) -> Tuple[str, str]:
    """Compute the idempotency keys."""

    raw_key = request.headers.get(PROVISIONING_HEADERS.idempotency_key_header, "").strip()
    method = request.method.upper()
    path = request.path

    tenant_id = getattr(request, "tenant_id", None) or "-"
    material = "||".join([raw_key, method, path, tenant_id])

    hashed_key = hashlib_sha256(material)
    payload_hash = hashlib_sha256(json.dumps(payload, sort_keys=True).encode("utf-8"))

    idempotency_logger.debug(
        "Computed idempotency hash",
        extra={"key": hashed_key, "tenant": tenant_id, "request_hash": payload_hash},
    )

    return hashed_key, payload_hash


def _reserve_durable_idempotency(
    factory: FirestoreServiceFactory,
    *,
    hashed_key: str,
    payload_hash: str,
) -> DurableReservation:
    """Reserve the durable idempotency."""

    try:
        repo = factory.get_idempotency_service()
    except Exception:
        idempotency_logger.warning("Durable idempotency repository unavailable")
        return DurableReservation(status="reserved", entry=None)

    ttl_hours = getattr(_org_flows_config(), "idempotency_ttl_hours", 24) or 24
    expires_at = int(time.time()) + int(ttl_hours * 3600)

    try:
        status, entry = repo.reserve(
            hashed_key,
            method=request.method,
            path=request.path,
            request_hash=payload_hash,
            tenant_id=None,
            expires_at=expires_at,
        )
        
        return DurableReservation(status=status, entry=entry)
    except FirestoreError as exc:
        idempotency_logger.warning("Failed to reserve durable idempotency", extra={"error": str(exc)})
        return DurableReservation(status="reserved", entry=None)


def _release_durable_idempotency(factory: FirestoreServiceFactory, hashed_key: str) -> None:
    """Release the durable idempotency."""
    
    try:
        factory.get_idempotency_service().delete(hashed_key)
    except Exception:
        pass


def _record_durable_response(factory: FirestoreServiceFactory, hashed_key: str, response: Response) -> None:
    """Record the durable response."""

    try:
        repo = factory.get_idempotency_service()
    except Exception:
        return

    body_bytes = response.get_data() or b""
    encoded_body = base64.b64encode(body_bytes).decode("ascii") if body_bytes else ""
    headers: MutableMapping[str, str] = {}

    for header, value in response.headers.items():
        if header.lower() in {"content-type", "content-language", "content-encoding"}:
            headers[header] = value

    repo.record_response(
        hashed_key,
        status_code=response.status_code,
        body_base64=encoded_body,
        headers=dict(headers),
    )


def _activate_verified_admin(
    factory: FirestoreServiceFactory,
    event: EmailVerifiedEvent,
    claims: Mapping[str, Any],
) -> EmailActivationResult:
    """Activate the verified admin."""

    client = factory.client

    try:
        outbox_repo = factory.get_outbox_service()
    except Exception:
        outbox_repo = None

    tenant_ref = client.collection("tenants").document(event.tenant_id)
    unique_key = _member_sentinel_key(event.tenant_id, event.email)
    unique_member_ref = client.collection("unique_members").document(unique_key)

    verified_at_ms = int(event.verified_at * 1000)
    utc_timestamp = datetime.utcfromtimestamp(event.verified_at).isoformat() + "Z"
    claim_snapshot = {
        key: claims.get(key)
        for key in ("jti", "nonce", "sub", "iss")
        if claims.get(key) is not None
    }

    state: dict[str, Any] = {
        "status": "noop",
        "member_id": None,
        "tenant_name": None,
    }

    transaction = client.transaction()

    def _txn(tx) -> None:
        """Transaction function to activate the verified admin."""

        tenant_snapshot = tenant_ref.get(transaction=tx)
        if not tenant_snapshot.exists:
            state["status"] = "tenant_missing"
            return

        tenant_data = tenant_snapshot.to_dict() or {}
        state["tenant_name"] = tenant_data.get("name")

        member_ref, member_snapshot = _resolve_member_for_activation(
            tx,
            tenant_ref.collection("members"),
            tenant_data,
            event,
        )

        if member_ref is None or member_snapshot is None:
            state["status"] = "member_missing"
            return

        state["member_id"] = member_snapshot.id
        member_data = member_snapshot.to_dict() or {}
        metadata = dict(member_data.get("metadata") or {})

        if _is_duplicate_verification(metadata, event.event_id):
            state["status"] = "noop"
            return

        if _update_if_already_active(
            tx,
            member_ref,
            metadata,
            event.event_id,
            verified_at_ms,
            member_data,
        ):
            state["status"] = "noop"
            return

        metadata = _enrich_verification_metadata(metadata, event.event_id, verified_at_ms, claim_snapshot)

        member_updates = _build_member_activation_updates(
            member_data,
            metadata,
            event.auth0_user_id,
            verified_at_ms,
        )
        tx.update(member_ref, member_updates)

        tenant_updates = _build_tenant_activation_updates(tenant_data, verified_at_ms)
        tx.update(tenant_ref, tenant_updates)

        created_at_int = _determine_member_created_at(member_data, metadata, verified_at_ms)
        sentinel_payload = _build_member_sentinel_payload(
            event,
            member_snapshot.id,
            created_at_int,
            verified_at_ms,
        )
        tx.set(unique_member_ref, sentinel_payload, merge=True)

        audit_doc = _build_activation_audit_doc(
            event,
            member_snapshot.id,
            verified_at_ms,
            utc_timestamp,
        )
        audit_ref = client.collection("audit_log").document()
        tx.set(audit_ref, audit_doc)

        if outbox_repo is not None:
            _enqueue_activation_outbox(
                tx,
                outbox_repo,
                event,
                tenant_data.get("name"),
                member_snapshot.id,
            )

        state["status"] = "activated"

    transaction.call(_txn)

    return EmailActivationResult(
        status=state.get("status", "noop"),
        tenant_id=event.tenant_id,
        member_id=state.get("member_id"),
        tenant_name=state.get("tenant_name"),
    )


def _resolve_member_for_activation(tx, members_collection, tenant_data: Mapping[str, Any], event: EmailVerifiedEvent):
    """Resolve the member for activation."""

    created_by = tenant_data.get("created_by_user_id")

    if isinstance(created_by, str) and created_by:
        candidate_ref = members_collection.document(created_by)
        snapshot = candidate_ref.get(transaction=tx)
        if snapshot.exists:
            return candidate_ref, snapshot

    query = members_collection.where("email", "==", event.email.lower()).limit(1)
    docs = list(query.stream(transaction=tx))

    if docs:
        snapshot = docs[0]
        return members_collection.document(snapshot.id), snapshot

    return None, None


def _is_duplicate_verification(metadata: Mapping[str, Any], event_id: str) -> bool:
    """Check if the verification is a duplicate."""
    
    return metadata.get("verificationEventId") == event_id


def _update_if_already_active(
    tx,
    member_ref,
    metadata: MutableMapping[str, Any],
    event_id: str,
    verified_at_ms: int,
    member_data: Mapping[str, Any],
) -> bool:
    """Update the member if already active."""
    
    current_status = str(member_data.get("status") or "").lower()
    if current_status != "active" or not member_data.get("auth0_user_id"):
        return False

    metadata.setdefault("verificationEventId", event_id)
    metadata.setdefault("verificationAt", verified_at_ms)

    tx.update(member_ref, {"metadata": dict(metadata), "updated_at": verified_at_ms})

    return True


def _enrich_verification_metadata(
    metadata: MutableMapping[str, Any],
    event_id: str,
    verified_at_ms: int,
    claim_snapshot: Mapping[str, Any],
) -> MutableMapping[str, Any]:
    """Enrich the verification metadata."""
    
    metadata.update(
        {
            "verificationEventId": event_id,
            "verificationAt": verified_at_ms,
        }
    )

    if claim_snapshot:
        metadata["verificationClaims"] = {k: str(v) for k, v in claim_snapshot.items()}

    return metadata


def _build_member_activation_updates(
    member_data: Mapping[str, Any],
    metadata: Mapping[str, Any],
    auth0_user_id: Optional[str],
    verified_at_ms: int,
) -> MutableMapping[str, Any]:
    """Build the member activation updates."""
    
    return {
        "status": "active",
        "auth0_user_id": auth0_user_id,
        "accepted_at": member_data.get("accepted_at") or verified_at_ms,
        "email_verified_at": verified_at_ms,
        "metadata": dict(metadata),
        "updated_at": verified_at_ms,
    }


def _build_tenant_activation_updates(tenant_data: Mapping[str, Any], verified_at_ms: int) -> MutableMapping[str, Any]:
    """Build the tenant activation updates."""
    
    counters = dict(tenant_data.get("counters") or {})
    pending_members = max(0, int(counters.get("pendingMembers", 0)) - 1)
    
    counters["pendingMembers"] = pending_members
    counters["members"] = max(int(counters.get("members", 1)), 1)

    updates: MutableMapping[str, Any] = {
        "status": TenantStatus.ACTIVE.value,
        "counters": counters,
        "updated_at": verified_at_ms,
    }

    if not tenant_data.get("activated_at"):
        updates["activated_at"] = verified_at_ms

    return updates


def _determine_member_created_at(
    member_data: Mapping[str, Any],
    metadata: Mapping[str, Any],
    verified_at_ms: int,
) -> int:
    """Determine the member created at."""
    
    created_at_source = member_data.get("invited_at") or metadata.get("invitedAt")

    try:
        return int(created_at_source) if created_at_source is not None else verified_at_ms
    except (TypeError, ValueError):
        return verified_at_ms


def _build_member_sentinel_payload(
    event: EmailVerifiedEvent,
    member_id: str,
    created_at: int,
    verified_at_ms: int,
) -> Mapping[str, Any]:
    """Build the member sentinel payload."""
    
    return {
        "tenant_id": event.tenant_id,
        "email": event.email.lower(),
        "member_id": member_id,
        "created_at": created_at,
        "updated_at": verified_at_ms,
    }


def _build_activation_audit_doc(
    event: EmailVerifiedEvent,
    member_id: str,
    verified_at_ms: int,
    utc_timestamp: str,
) -> Mapping[str, Any]:
    """Build the activation audit document."""
    
    return {
        "timestamp_ms": verified_at_ms,
        "utc_timestamp": utc_timestamp,
        "event_type": "TENANT_ADMIN_VERIFIED",
        "user_id": member_id,
        "username": event.email.lower(),
        "ip_address": request.remote_addr,
        "details": {
            "tenantId": event.tenant_id,
            "auth0UserId": event.auth0_user_id,
            "eventId": event.event_id,
        },
        "tenant_id": event.tenant_id,
    }


def _enqueue_activation_outbox(
    tx,
    outbox_repo,
    event: EmailVerifiedEvent,
    tenant_name: Optional[str],
    member_id: str,
) -> None:
    """Enqueue the activation outbox event."""
    
    outbox_event = OutboxEvent(
        event_id=f"tenant-admin-verified::{event.event_id}",
        topic="tenant.admin_verified",
        payload={
            "tenantId": event.tenant_id,
            "tenantName": tenant_name,
            "memberId": member_id,
            "adminEmail": event.email.lower(),
            "auth0UserId": event.auth0_user_id,
            "verifiedAt": event.verified_at,
        },
        status="pending",
        available_at=event.verified_at,
    )
    
    outbox_repo.enqueue(outbox_event, transaction=tx)


def _member_sentinel_key(tenant_id: str, email: str) -> str:
    """Build the member sentinel key."""

    normalized_email = (email or "").strip().lower()
    digest = hashlib_sha256(f"{tenant_id}::{normalized_email}")

    return f"{tenant_id}__{digest[:32]}"


class _InviteRateLimiter:
    """Simple in-memory per-tenant sliding window limiter."""

    def __init__(self) -> None:
        self._limiter = SlidingWindowLimiter()

    def allow(self, tenant_id: str, quota: int, window_seconds: int) -> bool:
        """Allow the invite rate limiter."""

        return self._limiter.allow(tenant_id, quota, window_seconds)


def _invite_rate_limiter_allow(tenant_id: str, quota: int, window_seconds: int) -> bool:
    """Allow the invite rate limiter."""

    limiter = current_app.config.setdefault("_invite_rate_limiter", _InviteRateLimiter())

    return bool(limiter.allow(tenant_id, quota, window_seconds))


def _derive_invited_member_id(email: str) -> str:
    """Derive the invited member id."""

    digest = hashlib_sha256((email or "").strip().lower())

    return f"invited_{digest[:24]}"


def _resolve_invite_actor() -> Tuple[Optional[str], Optional[str]]:
    """Resolve the invite actor."""

    ctx = getattr(request, "auth_context", None)

    if ctx is not None:
        username = getattr(ctx, "email", None)
        user_id = getattr(ctx, "subject", None)

        if username or user_id:
            return username, user_id

    session_obj = getattr(request, "session", None)
    if session_obj is not None:
        username = getattr(session_obj, "username", None)
        user_id = getattr(session_obj, "user_id", None)

        if username or user_id:
            return username, user_id

    return None, None


def _resolve_device_actor() -> Tuple[Optional[str], Optional[str]]:
    """Resolve the device actor."""

    return _resolve_invite_actor()


def _sanitize_request_claims(claims: Mapping[str, Any]) -> Mapping[str, Any]:
    """Sanitize the request claims."""

    allowed_keys = {"jti", "nonce", "sub", "iss", "scope", "event_id", "tenant_id", "tenantId"}

    sanitized: dict[str, Any] = {}

    for key in allowed_keys:
        value = claims.get(key)

        if value is not None:
            sanitized[key] = value

    return sanitized


def _finalize_invite_records(
    factory: FirestoreServiceFactory,
    *,
    tenant_id: str,
    member_id: str,
    invite_id: str,
    invite_token: Optional[str],
    schema: "InviteCreateRequest",
    actor_email: Optional[str],
    actor_user_id: Optional[str],
    request_claims: Mapping[str, Any],
    now_ms: int,
) -> str:
    """Finalize the invite records."""

    client = factory.client
    tenant_ref = client.collection("tenants").document(tenant_id)
    member_ref = tenant_ref.collection("members").document(member_id)
    sentinel_ref = client.collection("unique_members").document(_member_sentinel_key(tenant_id, schema.email))

    try:
        outbox_repo = factory.get_outbox_service()
    except Exception:
        outbox_repo = None

    audit_collection = client.collection("audit_log")
    state: dict[str, str] = {"status": "created"}

    transaction = client.transaction()

    def _txn(tx) -> None:
        """Transaction function to finalize the invite records."""

        tenant_snapshot = tenant_ref.get(transaction=tx)
        if not tenant_snapshot.exists:
            raise RequestTokenError("Tenant not found", code="TENANT_NOT_FOUND", status=404)

        sentinel_snapshot = sentinel_ref.get(transaction=tx)
        if sentinel_snapshot.exists:
            sentinel_data = sentinel_snapshot.to_dict() or {}

            if sentinel_data.get("invite_id") == invite_id:
                state["status"] = "noop"
                return

            raise InviteConflictError()

        member_snapshot = member_ref.get(transaction=tx)
        member_existing = member_snapshot.to_dict() if member_snapshot.exists else {}

        metadata = dict(member_existing.get("metadata") or {})
        metadata.update(
            {
                "inviteId": invite_id,
                "sendEmail": bool(schema.send_email),
            }
        )

        if request_claims:
            metadata["requestClaims"] = dict(request_claims)
        if schema.expires_in_hours is not None:
            metadata["expiresInHours"] = int(schema.expires_in_hours)
        if actor_email:
            metadata.setdefault("invitedByEmail", actor_email)
        if actor_user_id:
            metadata.setdefault("invitedByUserId", actor_user_id)

        member_payload: MutableMapping[str, Any] = {
            "tenant_id": tenant_id,
            "user_id": member_id,
            "email": schema.email.lower(),
            "role": schema.role.value,
            "status": "pending",
            "invited_at": member_existing.get("invited_at") or now_ms,
            "invited_by": schema.invited_by or actor_user_id or actor_email,
            "metadata": metadata,
            "updated_at": now_ms,
        }

        tx.set(member_ref, member_payload, merge=True)

        sentinel_payload = {
            "tenant_id": tenant_id,
            "email": schema.email.lower(),
            "member_id": member_id,
            "invite_id": invite_id,
            "status": "pending",
            "created_at": member_existing.get("invited_at") or now_ms,
            "updated_at": now_ms,
        }

        tx.set(sentinel_ref, sentinel_payload, merge=True)

        tenant_data = tenant_snapshot.to_dict() or {}
        counters = dict(tenant_data.get("counters") or {})
        counters["pendingMembers"] = int(counters.get("pendingMembers", 0)) + 1
        counters["invites"] = int(counters.get("invites", 0)) + 1

        tx.update(
            tenant_ref,
            {
                "counters": counters,
                "updated_at": now_ms,
            },
        )

        audit_doc = {
            "timestamp_ms": now_ms,
            "utc_timestamp": datetime.utcfromtimestamp(now_ms / 1000).isoformat() + "Z",
            "event_type": "INVITE_CREATED",
            "user_id": actor_user_id,
            "username": actor_email,
            "ip_address": request.remote_addr,
            "details": {
                "tenantId": tenant_id,
                "inviteId": invite_id,
                "inviteeEmail": schema.email.lower(),
            },
            "tenant_id": tenant_id,
        }

        tx.set(audit_collection.document(), audit_doc)

        if outbox_repo is not None and schema.send_email:
            outbox_event = OutboxEvent(
                event_id=f"tenant-invite-created::{invite_id}",
                topic="tenant.invite_created",
                payload={
                    "tenantId": tenant_id,
                    "inviteId": invite_id,
                    "email": schema.email,
                    "token": invite_token,
                    "role": schema.role.value,
                    "invitedBy": schema.invited_by or actor_email,
                    "metadata": metadata,
                },
                status="pending",
                available_at=int(time.time()),
            )
            outbox_repo.enqueue(outbox_event, transaction=tx)

    transaction.call(_txn)

    return state.get("status", "created")


def _execute_signup_transaction(
    factory: FirestoreServiceFactory,
    schema: OrgSignupRequest,
    claims: Mapping[str, Any],
    config,
    *,
    payload_hash: str,
) -> OrgSignupResponse:
    """Execute the signup transaction."""

    client = factory.client
    tenant_claim = claims.get(PROVISIONING_JWT.tenant_claim) or {}
    plan = None

    if isinstance(tenant_claim, Mapping):
        plan = tenant_claim.get("plan")

    slug = _determine_slug(schema, tenant_claim)
    tenant_id = f"tenant_{uuid.uuid4().hex[:18]}"
    admin_member_id = f"pending_admin_{uuid.uuid4().hex[:12]}"
    now_ms = int(time.time() * 1000)

    tenant_doc: MutableMapping[str, Any] = {
        "tenant_id": tenant_id,
        "name": schema.organization_name,
        "status": TenantStatus.PENDING_VERIFICATION.value,
        "slug": slug,
        "organization_id": tenant_id,
        "created_by_user_id": admin_member_id,
        "limits": {
            "maxDevices": getattr(config, "default_device_quota", 100) or 100,
            "maxUsers": 100,
            "maxInvitesPerWindow": getattr(config, "invite_quota_per_tenant", 20) or 20,
        },
        "settings": {
            "plan": plan or schema.plan,
            "marketingOptIn": bool(schema.marketing_opt_in),
        },
        "metadata": dict(schema.metadata or {}),
        "counters": {
            "members": 1,
            "devices": 0,
            "pendingMembers": 1,
            "invites": 0,
        },
        "created_at": now_ms,
        "updated_at": now_ms,
    }

    member_doc: MutableMapping[str, Any] = {
        "tenant_id": tenant_id,
        "user_id": admin_member_id,
        "email": schema.admin_email.lower(),
        "role": MemberRole.ADMIN.value,
        "status": "pending",
        "invited_at": now_ms,
        "first_name": schema.admin_first_name,
        "last_name": schema.admin_last_name,
        "metadata": {
            "requestHash": payload_hash,
        },
    }

    outbox_event = OutboxEvent(
        event_id=f"tenant-created::{tenant_id}",
        topic="tenant.created",
        payload={
            "tenantId": tenant_id,
            "organizationName": schema.organization_name,
            "adminEmail": schema.admin_email,
            "plan": plan or schema.plan,
        },
        status="pending",
        available_at=int(time.time()),
    )

    outbox_doc = outbox_event.to_dict()
    outbox_doc["created_at"] = now_ms
    outbox_doc["updated_at"] = now_ms

    tenant_ref = client.collection("tenants").document(tenant_id)
    member_ref = tenant_ref.collection("members").document(admin_member_id)
    outbox_ref = client.collection("outbox").document(outbox_event.event_id)

    transaction = client.transaction()

    def _txn(tx) -> None:
        """Transaction function to execute the signup transaction."""

        snapshot = tenant_ref.get(transaction=tx)

        if snapshot.exists:
            raise TenantConflictError()

        tx.set(tenant_ref, tenant_doc)
        tx.set(member_ref, member_doc)
        tx.set(outbox_ref, outbox_doc)

    try:
        transaction.call(_txn)
    except TenantConflictError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise TenantConflictError(str(exc)) from exc if "ALREADY_EXISTS" in str(exc) else exc

    _log_audit_event(factory, tenant_id, schema)

    logger.info(
        "Tenant signup transaction committed",
        extra={
            "tenant_id": tenant_id,
            "slug": slug,
        },
    )

    return OrgSignupResponse(
        tenant_id=tenant_id,
        status=TenantStatus.PENDING_VERIFICATION,
        verification_required=True,
    )


def _log_audit_event(factory: FirestoreServiceFactory, tenant_id: str, schema: OrgSignupRequest) -> None:
    """Log the audit event."""

    try:
        audit_store = factory.get_audit_service()
    except Exception:
        return

    try:
        audit_store.log_event(
            event_type="TENANT_CREATED",
            user_id=None,
            username=schema.admin_email.lower(),
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            details={
                "tenantId": tenant_id,
                "organizationName": schema.organization_name,
            },
            tenant_id=tenant_id,
        )
    except Exception:
        pass


def _determine_slug(schema: OrgSignupRequest, tenant_claim: Mapping[str, Any]) -> str:
    """Determine the slug."""

    token_slug = tenant_claim.get("tenant_slug") if isinstance(tenant_claim, Mapping) else None

    if isinstance(token_slug, str) and token_slug.strip():
        return _slugify(token_slug)

    return _slugify(schema.organization_name)


def _slugify(value: str) -> str:
    """Slugify the value."""

    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")

    if not slug:
        slug = f"tenant-{uuid.uuid4().hex[:6]}"

    return slug[:48]


def _response_from_durable_entry(entry: Any) -> Response:
    """Response from durable entry."""

    status_code = getattr(entry, "status_code", None) or 202
    body_base64 = getattr(entry, "response_body", "") or ""
    headers = getattr(entry, "response_headers", {}) or {}

    if body_base64:
        body_bytes = base64.b64decode(body_base64.encode("ascii"))
    else:
        body_bytes = json.dumps({"status": "pending"}).encode("utf-8")

    response = current_app.response_class(body_bytes, status=status_code)
    for header, value in headers.items():
        response.headers[header] = value

    response.headers["Idempotent-Replay"] = "true"
    response.headers.setdefault("Content-Type", "application/json")

    return response


def _verify_service_event_token() -> Mapping[str, Any]:
    """Verify the service event token."""

    auth_header = request.headers.get("Authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise OrgSignupError("Missing bearer token", code="AUTH_FAILED", status=401)

    prefix = os.getenv("SERVICE_JWT_PREFIX", "SERVICE_JWT") or "SERVICE_JWT"
    keyset_cache_key = "_org_signup_service_event_keyset"
    keyset = current_app.config.get(keyset_cache_key)

    if keyset is None:
        try:
            keyset = load_service_keyset_from_env(prefix=prefix)
        except Exception as exc:  # noqa: BLE001
            raise OrgSignupError("Service token verifier unavailable", code="AUTH_FAILED", status=503) from exc
        current_app.config[keyset_cache_key] = keyset

    cache = _email_event_replay_cache()

    try:
        claims = verify_service_jwt(
            token,
            keyset,
            audience=os.getenv("SERVICE_JWT_EXPECTED_AUDIENCE") or os.getenv("AUTH_SERVICE_TOKEN_AUDIENCE") or "bas-api",
            issuer=os.getenv("SERVICE_JWT_EXPECTED_ISSUER") or None,
            replay_cache=cache,
            required_scope=None,
        )
    except ServiceTokenValidationError as exc:
        raise OrgSignupError(str(exc), code="AUTH_FAILED", status=401) from exc

    subject = claims.get("sub")
    if subject != "auth.events.email_verified":
        raise OrgSignupError("Service token subject forbidden", code="AUTH_FORBIDDEN", status=403)

    return claims


def _verify_request_jwt(expected_tenant_id: str) -> Mapping[str, Any]:
    """Verify the request JWT."""

    token = request.headers.get(PROVISIONING_HEADERS.request_jwt_header)
    if not token or not token.strip():
        raise RequestTokenError("Signed request token required", code="REQUEST_JWT_MISSING", status=401)

    prefix = os.getenv("REQUEST_JWT_PREFIX", "REQUEST_JWT") or "REQUEST_JWT"
    keyset_cache_key = "_org_request_jwt_keyset"
    keyset = current_app.config.get(keyset_cache_key)

    if keyset is None:
        try:
            keyset = load_service_keyset_from_env(prefix=prefix)
        except Exception as exc:  # noqa: BLE001
            raise RequestTokenError("Request token verifier unavailable", code="REQUEST_JWT_UNAVAILABLE", status=503) from exc
        current_app.config[keyset_cache_key] = keyset

    replay_cache_key = "_org_request_jwt_replay_cache"
    replay_cache = current_app.config.get(replay_cache_key)

    if replay_cache is None:
        ttl_seconds = getattr(_org_flows_config(), "replay_cache_ttl_seconds", 120) or 120

        try:
            replay_cache = load_replay_cache_from_env(
                prefix=prefix,
                namespace="request-jwt",
                default_ttl_seconds=int(ttl_seconds),
                default_max_entries=2048,
            )
        except Exception:  # noqa: BLE001
            replay_cache = None
        if replay_cache is not None:
            current_app.config[replay_cache_key] = replay_cache

    audience = os.getenv("REQUEST_JWT_EXPECTED_AUDIENCE") or os.getenv("SERVICE_JWT_EXPECTED_AUDIENCE") or None
    issuer = os.getenv("REQUEST_JWT_EXPECTED_ISSUER") or None

    try:
        claims = verify_service_jwt(
            token,
            keyset,
            audience=audience,
            issuer=issuer,
            replay_cache=replay_cache,
            leeway_seconds=2,
        )
    except ServiceTokenValidationError as exc:
        raise RequestTokenError(str(exc)) from exc

    claim_tenant = claims.get("tenant_id") or claims.get("tenantId")
    if claim_tenant and str(claim_tenant) != expected_tenant_id:
        raise RequestTokenError("Request token tenant mismatch", code="REQUEST_JWT_TENANT_MISMATCH", status=403)

    return claims


def _email_event_replay_cache() -> Optional[ReplayCache]:
    """Create the email event replay cache."""

    cache_key = "_org_signup_email_event_replay_cache"
    cache = current_app.config.get(cache_key)

    if isinstance(cache, ReplayCache):
        return cache

    try:
        cache = load_replay_cache_from_env(prefix=os.getenv("SERVICE_JWT_PREFIX", "SERVICE_JWT") or "SERVICE_JWT", namespace="auth-email-events-api")
    except Exception:
        cache = None

    if cache is not None:
        current_app.config[cache_key] = cache

    return cache


def _create_device_record(
    factory: FirestoreServiceFactory,
    schema: DeviceRegistrationRequest,
    *,
    credential_record: DeviceCredentialRecord,
    actor_email: Optional[str],
    actor_user_id: Optional[str],
    request_claims: Mapping[str, Any],
    now_ms: int,
) -> DeviceRegistrationResponse:
    """Create the device record."""

    client = factory.client
    tenant_ref = client.collection("tenants").document(schema.tenant_id)
    device_ref = tenant_ref.collection("devices").document(schema.device_id)

    try:
        outbox_repo = factory.get_outbox_service()
    except Exception:  # noqa: BLE001
        outbox_repo = None

    try:
        audit_store = factory.get_audit_service()
    except Exception:  # noqa: BLE001
        audit_store = None

    config = _org_flows_config()
    if config is not None:
        default_quota = int(getattr(config, "default_device_quota", 100) or 100)
    else:
        default_quota = 100

    state: MutableMapping[str, Any] = {}
    transaction = client.transaction()

    def _txn(tx) -> None:
        """Transaction function to create the device record."""

        tenant_snapshot = tenant_ref.get(transaction=tx)
        if not tenant_snapshot.exists:
            raise DeviceNotFoundError("Tenant not found", code="TENANT_NOT_FOUND", status=404)

        tenant_data = tenant_snapshot.to_dict() or {}
        counters = dict(tenant_data.get("counters") or {})
        limits = tenant_data.get("limits") or {}

        max_devices = int(limits.get("maxDevices") or default_quota)
        current_devices = int(counters.get("devices", 0))

        if max_devices and current_devices >= max_devices:
            raise DeviceQuotaExceededError()

        device_snapshot = device_ref.get(transaction=tx)
        if device_snapshot.exists:
            existing = device_snapshot.to_dict() or {}
            if not existing.get("deleted_at"):
                raise DeviceConflictError()

        metadata = dict(schema.metadata or {})
        metadata.setdefault("hardwareId", schema.hardware_id)
        metadata.setdefault("displayName", schema.display_name)
        metadata.setdefault("provisionedAt", now_ms)

        if actor_user_id:
            metadata.setdefault("addedByUserId", actor_user_id)
        if actor_email:
            metadata.setdefault("addedByEmail", actor_email)
        if request_claims:
            metadata["requestClaims"] = dict(request_claims)

        device_payload: MutableMapping[str, Any] = {
            "tenant_id": schema.tenant_id,
            "device_id": schema.device_id,
            "display_name": schema.display_name,
            "hardware_id": schema.hardware_id,
            "metadata": metadata,
            "tags": list(schema.tags),
            "status": DeviceLifecycle.ACTIVE.value,
            "credentials_ref": credential_record.credential_reference,
            "added_by_user_id": actor_user_id,
            "added_by_email": actor_email,
            "created_at": now_ms,
            "updated_at": now_ms,
        }
        device_payload = {k: v for k, v in device_payload.items() if v is not None}

        tx.set(device_ref, device_payload)
        counters["devices"] = current_devices + 1
        tx.update(
            tenant_ref,
            {
                "counters": counters,
                "updated_at": now_ms,
            },
        )

        state["tenant_name"] = tenant_data.get("name")

        if outbox_repo is not None:
            created_event = OutboxEvent(
                event_id=f"tenant-device-created::{schema.tenant_id}::{schema.device_id}",
                topic="tenant.device_created",
                payload={
                    "tenantId": schema.tenant_id,
                    "deviceId": schema.device_id,
                    "displayName": schema.display_name,
                    "hardwareId": schema.hardware_id,
                    "credentialRef": credential_record.credential_reference,
                },
                status="pending",
                available_at=int(time.time()),
            )

            outbox_repo.enqueue(created_event, transaction=tx)

            rotation_event = OutboxEvent(
                event_id=(
                    f"tenant-device-rotation::{schema.tenant_id}::{schema.device_id}::"
                    f"{credential_record.rotation_due_at}"
                ),
                topic="tenant.device_rotation.scheduled",
                payload={
                    "tenantId": schema.tenant_id,
                    "deviceId": schema.device_id,
                    "credentialRef": credential_record.credential_reference,
                    "rotationDueAt": credential_record.rotation_due_at,
                },
                status="pending",
                available_at=int(credential_record.rotation_due_at),
            )

            outbox_repo.enqueue(rotation_event, transaction=tx)

    transaction.call(_txn)

    _log_device_audit_event(
        audit_store,
        action="DEVICE_CREATED",
        tenant_id=schema.tenant_id,
        device_id=schema.device_id,
        actor_email=actor_email,
        actor_user_id=actor_user_id,
        now_ms=now_ms,
        details={
            "credentialRef": credential_record.credential_reference,
            "tenantName": state.get("tenant_name"),
        },
    )
    """Log the device audit event."""

    return DeviceRegistrationResponse(
        device_id=schema.device_id,
        lifecycle=DeviceLifecycle.ACTIVE.value,
        credential_ref=credential_record.credential_reference,
    )


def _soft_delete_device_record(
    factory: FirestoreServiceFactory,
    *,
    tenant_id: str,
    device_id: str,
    actor_email: Optional[str],
    actor_user_id: Optional[str],
    request_claims: Mapping[str, Any],
    now_ms: int,
) -> MutableMapping[str, Any]:
    """Soft delete the device record."""

    client = factory.client
    tenant_ref = client.collection("tenants").document(tenant_id)
    device_ref = tenant_ref.collection("devices").document(device_id)

    try:
        outbox_repo = factory.get_outbox_service()
    except Exception:  # noqa: BLE001
        outbox_repo = None

    try:
        audit_store = factory.get_audit_service()
    except Exception:  # noqa: BLE001
        audit_store = None

    state: MutableMapping[str, Any] = {"status": "deleted", "credential_ref": None}
    transaction = client.transaction()

    def _txn(tx) -> None:
        """Transaction function to soft delete the device record."""

        tenant_snapshot = tenant_ref.get(transaction=tx)
        if not tenant_snapshot.exists:
            raise DeviceNotFoundError("Tenant not found", code="TENANT_NOT_FOUND", status=404)

        tenant_data = tenant_snapshot.to_dict() or {}
        state["tenant_name"] = tenant_data.get("name")

        device_snapshot = device_ref.get(transaction=tx)
        if not device_snapshot.exists:
            raise DeviceNotFoundError()

        device_data = device_snapshot.to_dict() or {}
        credential_ref = device_data.get("credentials_ref")

        if credential_ref:
            state["credential_ref"] = credential_ref

        if device_data.get("deleted_at"):
            state["status"] = "noop"
            return

        metadata = dict(device_data.get("metadata") or {})
        if request_claims:
            metadata["deleteRequestClaims"] = dict(request_claims)
        if actor_user_id:
            metadata["deletedByUserId"] = actor_user_id
        if actor_email:
            metadata["deletedByEmail"] = actor_email

        updates: MutableMapping[str, Any] = {
            "status": DeviceLifecycle.DECOMMISSIONED.value,
            "deleted_at": now_ms,
            "updated_at": now_ms,
            "metadata": metadata,
        }

        tx.update(device_ref, updates)

        counters = dict(tenant_data.get("counters") or {})
        counters["devices"] = max(0, int(counters.get("devices", 0)) - 1)
        tx.update(
            tenant_ref,
            {
                "counters": counters,
                "updated_at": now_ms,
            },
        )

        if outbox_repo is not None:
            deleted_event = OutboxEvent(
                event_id=f"tenant-device-deleted::{tenant_id}::{device_id}::{now_ms}",
                topic="tenant.device_deleted",
                payload={
                    "tenantId": tenant_id,
                    "deviceId": device_id,
                    "credentialRef": credential_ref,
                },
                status="pending",
                available_at=int(time.time()),
            )
            outbox_repo.enqueue(deleted_event, transaction=tx)

            if credential_ref:
                revoke_event = OutboxEvent(
                    event_id=f"tenant-device-credential-revoke::{tenant_id}::{device_id}::{now_ms}",
                    topic="tenant.device_credentials.revoke",
                    payload={
                        "tenantId": tenant_id,
                        "deviceId": device_id,
                        "credentialRef": credential_ref,
                    },
                    status="pending",
                    available_at=int(time.time()),
                )
                outbox_repo.enqueue(revoke_event, transaction=tx)

    transaction.call(_txn)

    _log_device_audit_event(
        audit_store,
        action="DEVICE_DELETED",
        tenant_id=tenant_id,
        device_id=device_id,
        actor_email=actor_email,
        actor_user_id=actor_user_id,
        now_ms=now_ms,
        details={
            "credentialRef": state.get("credential_ref"),
            "status": state.get("status"),
            "tenantName": state.get("tenant_name"),
        },
    )
    """Return the device record."""

    return {
        "status": state.get("status", "deleted"),
        "deviceId": device_id,
        "credentialRef": state.get("credential_ref"),
    }


def _serialize_device(device: Any) -> MutableMapping[str, Any]:
    """Serialize the device."""

    tags = list(getattr(device, "tags", []) or [])
    data: MutableMapping[str, Any] = {
        "deviceId": getattr(device, "device_id", None),
        "displayName": getattr(device, "display_name", None),
        "hardwareId": getattr(device, "hardware_id", None),
        "status": getattr(device, "status", None),
        "lifecycle": getattr(device, "status", None),
        "tags": tags,
        "lastSeen": getattr(device, "last_seen", None),
        "credentialRef": getattr(device, "credentials_ref", None),
        "addedByUserId": getattr(device, "added_by_user_id", None),
        "addedByEmail": getattr(device, "added_by_email", None),
        "createdAt": getattr(device, "created_at", None),
        "updatedAt": getattr(device, "updated_at", None),
        "deletedAt": getattr(device, "deleted_at", None),
        "metadata": getattr(device, "metadata", None),
    }

    return {k: v for k, v in data.items() if v is not None}


def _log_device_audit_event(
    audit_store: Any,
    *,
    action: str,
    tenant_id: str,
    device_id: str,
    actor_email: Optional[str],
    actor_user_id: Optional[str],
    now_ms: int,
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    """Log the device audit event."""

    payload = {
        "tenantId": tenant_id,
        "deviceId": device_id,
    }

    if details:
        payload.update({k: v for k, v in details.items() if v is not None})

    try:
        if audit_store is not None and hasattr(audit_store, "log_event"):
            audit_store.log_event(
                event_type=action,
                user_id=actor_user_id,
                username=actor_email,
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
                details=payload,
                tenant_id=tenant_id,
            )
            return
    except Exception:  # noqa: BLE001
        pass

    try:
        audit_logger = getattr(request, "audit_logger", None)
        if audit_logger and hasattr(audit_logger, "log_event"):
            audit_logger.log_event(action, payload)
    except Exception:  # noqa: BLE001
        pass


def _json_error(message: str, code: str, status: int, *, details: Optional[str] = None) -> Response:
    """Return a JSON error response."""

    payload: MutableMapping[str, Any] = {"error": message, "code": code}

    if details:
        payload["details"] = details

    response = jsonify(payload)
    response.status_code = status

    return response


def _error_response(error: OrgSignupError) -> Response:
    """Return an error response."""

    return _json_error(error.message, error.code, error.status)


def hashlib_sha256(value: Any) -> str:
    """Hash the value using SHA-256."""
    
    if isinstance(value, str):
        data = value.encode("utf-8")
    elif isinstance(value, bytes):
        data = value
    else:
        data = str(value).encode("utf-8")

    import hashlib

    return hashlib.sha256(data).hexdigest()


def _coerce_int(value: Any, *, default: int, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    """Coerce the value to an integer."""

    try:
        parsed = int(value)
    except Exception:
        return default

    if minimum is not None and parsed < minimum:
        parsed = minimum

    if maximum is not None and parsed > maximum:
        parsed = maximum
        
    return parsed


__all__ = ["org_bp"]


