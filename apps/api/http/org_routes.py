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
from typing import Any, Mapping, MutableMapping, Optional, Tuple

from flask import Blueprint, Response, current_app, jsonify, request

from logging_lib import get_logger as get_structured_logger

from adapters.db.firestore.base import FirestoreError
from adapters.db.firestore.models import OutboxEvent
from adapters.db.firestore.service_factory import FirestoreServiceFactory
from app_platform.contracts import (
    PROVISIONING_HEADERS,
    PROVISIONING_JWT,
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
from apps.api.http.middleware import enforce_idempotency
from apps.api.http.schemas import SchemaValidationError
from apps.api.http.schemas.org import (
    EmailVerifiedEvent,
    OrgSignupRequest,
    OrgSignupResponse,
    parse_email_verified_event,
    parse_org_signup,
)


org_bp = Blueprint("orgs", __name__)

logger = get_structured_logger("api.http.orgs")
captcha_logger = get_structured_logger("api.http.orgs.captcha")
idempotency_logger = get_structured_logger("api.http.orgs.idempotency")
events_logger = get_structured_logger("api.http.orgs.events")


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


@dataclass(slots=True)
class DurableReservation:
    status: str
    entry: Optional[Any]


@dataclass(slots=True)
class EmailActivationResult:
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


# ---------------------------------------------------------------------------
# Helper routines
# ---------------------------------------------------------------------------


def _org_signup_enabled() -> bool:
    flag = current_app.config.get("org_signup_v2_enabled")
    if flag is None:
        server = getattr(request, "server_config", None)
        try:
            return bool(getattr(getattr(server, "org_flows", None), "org_signup_v2_enabled", False))
        except Exception:
            return False
    return bool(flag)


def _org_flows_config():
    config = current_app.config.get("org_flows_config")
    if config is not None:
        return config
    server = getattr(request, "server_config", None)
    return getattr(server, "org_flows", None)


def _resolve_firestore_factory() -> Optional[FirestoreServiceFactory]:
    direct = current_app.config.get("firestore_factory")
    if direct:
        return direct
    return getattr(request, "firestore_factory", None)


def _verify_captcha_if_required(schema: OrgSignupRequest, config) -> None:
    provider = getattr(config, "captcha_provider", None) if config else None
    secret_handle = getattr(config, "captcha_secret_handle", None) if config else None
    if not provider:
        return
    verifier = _captcha_verifier(provider, secret_handle, getattr(config, "captcha_min_score", 0.5), getattr(config, "captcha_site_key", None))
    if verifier is None:
        return
    verifier.verify(schema.captcha_token, remote_addr=request.remote_addr)


def _captcha_verifier(provider: str, secret_handle: Optional[str], min_score: float, site_key: Optional[str]) -> Optional[CaptchaVerifier]:
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
    try:
        factory.get_idempotency_service().delete(hashed_key)
    except Exception:
        pass


def _record_durable_response(factory: FirestoreServiceFactory, hashed_key: str, response: Response) -> None:
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
        tenant_snapshot = tenant_ref.get(transaction=tx)
        if not tenant_snapshot.exists:
            state["status"] = "tenant_missing"
            return

        tenant_data = tenant_snapshot.to_dict() or {}
        state["tenant_name"] = tenant_data.get("name")
        members_collection = tenant_ref.collection("members")

        member_ref = None
        member_snapshot = None
        created_by = tenant_data.get("created_by_user_id")
        if isinstance(created_by, str) and created_by:
            candidate_ref = members_collection.document(created_by)
            snapshot = candidate_ref.get(transaction=tx)
            if snapshot.exists:
                member_ref = candidate_ref
                member_snapshot = snapshot

        if member_snapshot is None or not member_snapshot.exists:
            query = members_collection.where("email", "==", event.email.lower()).limit(1)
            docs = list(query.stream(transaction=tx))
            if docs:
                member_snapshot = docs[0]
                member_ref = members_collection.document(member_snapshot.id)

        if member_snapshot is None or not member_snapshot.exists or member_ref is None:
            state["status"] = "member_missing"
            return

        state["member_id"] = member_snapshot.id
        member_data = member_snapshot.to_dict() or {}

        metadata = dict(member_data.get("metadata") or {})
        if metadata.get("verificationEventId") == event.event_id:
            state["status"] = "noop"
            return

        current_status = str(member_data.get("status") or "").lower()
        if current_status == "active" and member_data.get("auth0_user_id"):
            metadata.setdefault("verificationEventId", event.event_id)
            metadata.setdefault("verificationAt", verified_at_ms)
            tx.update(member_ref, {"metadata": metadata, "updated_at": verified_at_ms})
            state["status"] = "noop"
            return

        metadata.update(
            {
                "verificationEventId": event.event_id,
                "verificationAt": verified_at_ms,
            }
        )
        if claim_snapshot:
            metadata["verificationClaims"] = {k: str(v) for k, v in claim_snapshot.items()}

        member_updates: MutableMapping[str, Any] = {
            "status": "active",
            "auth0_user_id": event.auth0_user_id,
            "accepted_at": member_data.get("accepted_at") or verified_at_ms,
            "email_verified_at": verified_at_ms,
            "metadata": metadata,
            "updated_at": verified_at_ms,
        }

        tx.update(member_ref, member_updates)

        counters = dict(tenant_data.get("counters") or {})
        pending_members = max(0, int(counters.get("pendingMembers", 0)) - 1)
        counters["pendingMembers"] = pending_members
        counters["members"] = max(int(counters.get("members", 1)), 1)

        tenant_updates: MutableMapping[str, Any] = {
            "status": TenantStatus.ACTIVE.value,
            "counters": counters,
            "updated_at": verified_at_ms,
        }
        if not tenant_data.get("activated_at"):
            tenant_updates["activated_at"] = verified_at_ms

        tx.update(tenant_ref, tenant_updates)

        created_at_source = member_data.get("invited_at") or metadata.get("invitedAt")
        try:
            created_at_int = int(created_at_source) if created_at_source is not None else verified_at_ms
        except (TypeError, ValueError):
            created_at_int = verified_at_ms
        sentinel_payload = {
            "tenant_id": event.tenant_id,
            "email": event.email.lower(),
            "member_id": member_snapshot.id,
            "created_at": created_at_int,
            "updated_at": verified_at_ms,
        }
        tx.set(unique_member_ref, sentinel_payload, merge=True)

        audit_doc = {
            "timestamp_ms": verified_at_ms,
            "utc_timestamp": utc_timestamp,
            "event_type": "TENANT_ADMIN_VERIFIED",
            "user_id": member_snapshot.id,
            "username": event.email.lower(),
            "ip_address": request.remote_addr,
            "details": {
                "tenantId": event.tenant_id,
                "auth0UserId": event.auth0_user_id,
                "eventId": event.event_id,
            },
            "tenant_id": event.tenant_id,
        }
        audit_ref = client.collection("audit_log").document()
        tx.set(audit_ref, audit_doc)

        if outbox_repo is not None:
            outbox_event = OutboxEvent(
                event_id=f"tenant-admin-verified::{event.event_id}",
                topic="tenant.admin_verified",
                payload={
                    "tenantId": event.tenant_id,
                    "tenantName": tenant_data.get("name"),
                    "memberId": member_snapshot.id,
                    "adminEmail": event.email.lower(),
                    "auth0UserId": event.auth0_user_id,
                    "verifiedAt": event.verified_at,
                },
                status="pending",
                available_at=event.verified_at,
            )
            outbox_repo.enqueue(outbox_event, transaction=tx)

        state["status"] = "activated"

    transaction.call(_txn)

    return EmailActivationResult(
        status=state.get("status", "noop"),
        tenant_id=event.tenant_id,
        member_id=state.get("member_id"),
        tenant_name=state.get("tenant_name"),
    )


def _member_sentinel_key(tenant_id: str, email: str) -> str:
    normalized_email = (email or "").strip().lower()
    digest = hashlib_sha256(f"{tenant_id}::{normalized_email}")
    return f"{tenant_id}__{digest[:32]}"


def _execute_signup_transaction(
    factory: FirestoreServiceFactory,
    schema: OrgSignupRequest,
    claims: Mapping[str, Any],
    config,
    *,
    payload_hash: str,
) -> OrgSignupResponse:
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
    token_slug = tenant_claim.get("tenant_slug") if isinstance(tenant_claim, Mapping) else None
    if isinstance(token_slug, str) and token_slug.strip():
        return _slugify(token_slug)
    return _slugify(schema.organization_name)


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not slug:
        slug = f"tenant-{uuid.uuid4().hex[:6]}"
    return slug[:48]


def _response_from_durable_entry(entry: Any) -> Response:
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


def _email_event_replay_cache() -> Optional[ReplayCache]:
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


def _json_error(message: str, code: str, status: int, *, details: Optional[str] = None) -> Response:
    payload: MutableMapping[str, Any] = {"error": message, "code": code}
    if details:
        payload["details"] = details
    response = jsonify(payload)
    response.status_code = status
    return response


def _error_response(error: OrgSignupError) -> Response:
    return _json_error(error.message, error.code, error.status)


def hashlib_sha256(value: Any) -> str:
    if isinstance(value, str):
        data = value.encode("utf-8")
    elif isinstance(value, bytes):
        data = value
    else:
        data = str(value).encode("utf-8")
    import hashlib

    return hashlib.sha256(data).hexdigest()


__all__ = ["org_bp"]


