"""Schema definitions for organization onboarding flows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, MutableMapping, Optional

from app_platform.contracts import InviteStatus, MemberRole, TenantStatus

from .base import (
    BaseSchema,
    SchemaValidationError,
    _ensure_email,
    _ensure_plan,
    _ensure_tags,
    _optional_str,
)


def _extract(payload: Mapping[str, Any] | MutableMapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in payload:
            return payload[name]
    return None


def _normalize_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise SchemaValidationError(f"Field '{field}' must be a string")
    normalized = value.strip()
    if not normalized:
        raise SchemaValidationError(f"Field '{field}' is required")
    return normalized


@dataclass(slots=True)
class OrgSignupRequest(BaseSchema):
    organization_name: str
    admin_email: str
    admin_first_name: str
    admin_last_name: str
    plan: Optional[str] = None
    captcha_token: Optional[str] = None
    provisioning_jwt: Optional[str] = None
    marketing_opt_in: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class OrgSignupResponse(BaseSchema):
    tenant_id: str
    status: TenantStatus
    verification_required: bool = True


def parse_org_signup(payload: Mapping[str, Any] | MutableMapping[str, Any]) -> OrgSignupRequest:
    name = _normalize_str(_extract(payload, "organizationName", "organization_name"), "organization_name")
    admin_email = _ensure_email(_extract(payload, "adminEmail", "admin_email"), "admin_email")
    admin_first_name = _normalize_str(_extract(payload, "adminFirstName", "admin_first_name"), "admin_first_name")
    admin_last_name = _normalize_str(_extract(payload, "adminLastName", "admin_last_name"), "admin_last_name")

    plan = _ensure_plan(_extract(payload, "plan", "pricingPlan"))
    captcha = _optional_str(_extract(payload, "captchaToken", "captcha_token"))
    provisioning = _optional_str(_extract(payload, "provisioningJwt", "provisioning_jwt"))
    marketing_opt_in = bool(payload.get("marketingOptIn") or payload.get("marketing_opt_in", False))
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), Mapping) else {}

    return OrgSignupRequest(
        organization_name=name,
        admin_email=admin_email,
        admin_first_name=admin_first_name,
        admin_last_name=admin_last_name,
        plan=plan,
        captcha_token=captcha,
        provisioning_jwt=provisioning,
        marketing_opt_in=marketing_opt_in,
        metadata=metadata,
    )


@dataclass(slots=True)
class InviteCreateRequest(BaseSchema):
    tenant_id: str
    email: str
    role: MemberRole
    invited_by: Optional[str] = None
    send_email: bool = True
    expires_in_hours: Optional[int] = None
    captcha_token: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class InviteCreateResponse(BaseSchema):
    invite_id: str
    status: InviteStatus


def parse_invite_create(
    payload: Mapping[str, Any] | MutableMapping[str, Any],
    *,
    tenant_id: str,
) -> InviteCreateRequest:
    email = _ensure_email(_extract(payload, "email", "inviteeEmail"), "email")
    role_value = _normalize_str(_extract(payload, "role", "memberRole"), "role").lower()
    try:
        role = MemberRole(role_value)
    except ValueError as exc:
        raise SchemaValidationError("Unsupported invite role", errors=[role_value]) from exc

    send_email = bool(payload.get("sendEmail", payload.get("send_email", True)))

    expires_in = payload.get("expiresInHours") or payload.get("expires_in_hours")
    if expires_in is not None:
        if not isinstance(expires_in, int) or expires_in <= 0:
            raise SchemaValidationError("expires_in_hours must be positive integer")

    captcha = _optional_str(_extract(payload, "captchaToken", "captcha_token"))
    invited_by = _optional_str(_extract(payload, "invitedBy", "invited_by"))
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), Mapping) else {}

    return InviteCreateRequest(
        tenant_id=_normalize_str(tenant_id, "tenant_id"),
        email=email,
        role=role,
        invited_by=invited_by,
        send_email=send_email,
        expires_in_hours=expires_in,
        captcha_token=captcha,
        metadata=metadata,
    )


@dataclass(slots=True)
class DeviceRegistrationRequest(BaseSchema):
    tenant_id: str
    device_id: Optional[str]
    display_name: str
    hardware_id: str
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DeviceRegistrationResponse(BaseSchema):
    device_id: str
    lifecycle: str


def parse_device_registration(
    payload: Mapping[str, Any] | MutableMapping[str, Any],
    *,
    tenant_id: str,
) -> DeviceRegistrationRequest:
    display_name = _normalize_str(_extract(payload, "displayName", "display_name"), "display_name")
    hardware_id = _normalize_str(_extract(payload, "hardwareId", "hardware_id"), "hardware_id")
    device_id = _optional_str(_extract(payload, "deviceId", "device_id"))
    tags = _ensure_tags(payload.get("tags"))
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), Mapping) else {}

    return DeviceRegistrationRequest(
        tenant_id=_normalize_str(tenant_id, "tenant_id"),
        device_id=device_id,
        display_name=display_name,
        hardware_id=hardware_id,
        tags=tags,
        metadata=metadata,
    )


@dataclass(slots=True)
class EmailVerifiedEvent(BaseSchema):
    event_id: str
    auth0_user_id: str
    email: str
    tenant_id: str
    verified_at: int
    metadata: Mapping[str, Any] = field(default_factory=dict)


def parse_email_verified_event(payload: Mapping[str, Any] | MutableMapping[str, Any]) -> EmailVerifiedEvent:
    if not isinstance(payload, Mapping):
        raise SchemaValidationError("Webhook payload must be an object")

    event_id = _normalize_str(_extract(payload, "eventId", "event_id"), "event_id")
    auth0_user_id = _normalize_str(
        _extract(payload, "auth0UserId", "auth0_user_id", "userId", "user_id"),
        "auth0_user_id",
    )
    email = _ensure_email(_extract(payload, "email", "userEmail"), "email")
    tenant_id = _normalize_str(_extract(payload, "tenantId", "tenant_id"), "tenant_id")

    verified_at_raw = _extract(payload, "verifiedAt", "verified_at", "timestamp")
    if verified_at_raw is None:
        raise SchemaValidationError("Missing verified_at timestamp")
    try:
        verified_at = int(verified_at_raw)
    except (TypeError, ValueError) as exc:
        raise SchemaValidationError("verified_at must be an integer epoch seconds") from exc

    metadata = payload.get("metadata")
    if metadata is None:
        metadata = {}
    elif not isinstance(metadata, Mapping):
        raise SchemaValidationError("metadata must be an object when provided")

    return EmailVerifiedEvent(
        event_id=event_id,
        auth0_user_id=auth0_user_id,
        email=email,
        tenant_id=tenant_id,
        verified_at=verified_at,
        metadata=dict(metadata),
    )


__all__ = [
    "DeviceRegistrationRequest",
    "DeviceRegistrationResponse",
    "InviteCreateRequest",
    "InviteCreateResponse",
    "EmailVerifiedEvent",
    "OrgSignupRequest",
    "OrgSignupResponse",
    "parse_device_registration",
    "parse_invite_create",
    "parse_org_signup",
    "parse_email_verified_event",
]


