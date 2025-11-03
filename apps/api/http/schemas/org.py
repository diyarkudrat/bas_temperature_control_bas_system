"""Schema definitions for organization onboarding flows."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, MutableMapping, Optional, cast

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
    """Extract a value from the payload."""

    for name in names:
        if name in payload:
            return payload[name]

    return None


def _normalize_str(value: Any, field: str) -> str:
    """Normalize a string value."""

    if not isinstance(value, str):
        raise SchemaValidationError(f"Field '{field}' must be a string")

    normalized = value.strip()
    if not normalized:
        raise SchemaValidationError(f"Field '{field}' is required")

    return normalized


def _empty_metadata() -> Mapping[str, Any]:
    """Return an immutable empty metadata mapping."""

    return MappingProxyType({})


def _wrap_metadata(metadata: Mapping[str, Any] | None) -> Mapping[str, Any]:
    """Return an immutable copy of provided metadata mapping."""

    if metadata is None:
        return _empty_metadata()

    return MappingProxyType(dict(metadata))


@dataclass(slots=True, frozen=True)
class OrgSignupRequest(BaseSchema):
    """Request for organization signup."""

    organization_name: str # The name of the organization
    admin_email: str # The email of the admin user
    admin_first_name: str # The first name of the admin user
    admin_last_name: str # The last name of the admin user
    plan: Optional[str] = None # The plan for the organization
    captcha_token: Optional[str] = None # The captcha token
    provisioning_jwt: Optional[str] = None # The provisioning JWT
    marketing_opt_in: bool = False # Whether the admin user has opted in to marketing
    metadata: Mapping[str, Any] = field(default_factory=_empty_metadata) # The metadata for the organization


@dataclass(slots=True, frozen=True)
class OrgSignupResponse(BaseSchema):
    """Response for organization signup."""

    tenant_id: str # The ID of the tenant
    status: TenantStatus # The status of the tenant
    verification_required: bool = True # Whether verification is required


def parse_org_signup(payload: Mapping[str, Any] | MutableMapping[str, Any]) -> OrgSignupRequest:
    """Parse the organization signup request."""

    name = _normalize_str(_extract(payload, "organizationName", "organization_name"), "organization_name")
    admin_email = _ensure_email(_extract(payload, "adminEmail", "admin_email"), "admin_email")
    admin_first_name = _normalize_str(_extract(payload, "adminFirstName", "admin_first_name"), "admin_first_name")
    admin_last_name = _normalize_str(_extract(payload, "adminLastName", "admin_last_name"), "admin_last_name")

    plan = _ensure_plan(_extract(payload, "plan", "pricingPlan"))
    captcha = _optional_str(_extract(payload, "captchaToken", "captcha_token"))
    provisioning = _optional_str(_extract(payload, "provisioningJwt", "provisioning_jwt"))
    marketing_opt_in = bool(payload.get("marketingOptIn") or payload.get("marketing_opt_in", False))
    metadata_payload = payload.get("metadata")
    metadata = _wrap_metadata(metadata_payload if isinstance(metadata_payload, Mapping) else None)

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


@dataclass(slots=True, frozen=True)
class InviteCreateRequest(BaseSchema):
    """Request for invite creation."""

    tenant_id: str
    email: str
    role: MemberRole
    invited_by: Optional[str] = None
    send_email: bool = True
    expires_in_hours: Optional[int] = None
    captcha_token: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=_empty_metadata)


@dataclass(slots=True, frozen=True)
class InviteCreateResponse(BaseSchema):
    """Response for invite creation."""

    invite_id: str
    status: InviteStatus


def parse_invite_create(
    payload: Mapping[str, Any] | MutableMapping[str, Any],
    *,
    tenant_id: str,
) -> InviteCreateRequest:
    """Parse the invite creation request."""

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

    metadata_payload = payload.get("metadata")
    metadata = _wrap_metadata(metadata_payload if isinstance(metadata_payload, Mapping) else None)

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


@dataclass(slots=True, frozen=True)
class DeviceRegistrationRequest(BaseSchema):
    """Request for device registration."""

    tenant_id: str
    device_id: Optional[str]
    display_name: str
    hardware_id: str
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=_empty_metadata)


@dataclass(slots=True, frozen=True)
class DeviceRegistrationResponse(BaseSchema):
    """Response for device registration."""

    device_id: str
    lifecycle: str
    credential_ref: Optional[str] = None


def parse_device_registration(
    payload: Mapping[str, Any] | MutableMapping[str, Any],
    *,
    tenant_id: str,
) -> DeviceRegistrationRequest:
    """Parse the device registration request."""

    display_name = _normalize_str(_extract(payload, "displayName", "display_name"), "display_name")
    hardware_id = _normalize_str(_extract(payload, "hardwareId", "hardware_id"), "hardware_id")
    device_id = _optional_str(_extract(payload, "deviceId", "device_id"))
    tags = _ensure_tags(payload.get("tags"))
    metadata_payload = payload.get("metadata")
    metadata = _wrap_metadata(metadata_payload if isinstance(metadata_payload, Mapping) else None)

    return DeviceRegistrationRequest(
        tenant_id=_normalize_str(tenant_id, "tenant_id"),
        device_id=device_id,
        display_name=display_name,
        hardware_id=hardware_id,
        tags=tags,
        metadata=metadata,
    )


@dataclass(slots=True, frozen=True)
class EmailVerifiedEvent(BaseSchema):
    """Event for email verification."""

    event_id: str
    auth0_user_id: str
    email: str
    tenant_id: str
    verified_at: int
    metadata: Mapping[str, Any] = field(default_factory=_empty_metadata)


def parse_email_verified_event(payload: object) -> EmailVerifiedEvent:
    """Parse the email verified event."""
    
    if not isinstance(payload, Mapping):
        raise SchemaValidationError("Webhook payload must be an object")

    payload_mapping = cast(Mapping[str, Any] | MutableMapping[str, Any], payload)

    event_id = _normalize_str(_extract(payload_mapping, "eventId", "event_id"), "event_id")
    auth0_user_id = _normalize_str(
        _extract(payload_mapping, "auth0UserId", "auth0_user_id", "userId", "user_id"),
        "auth0_user_id",
    )
    email = _ensure_email(_extract(payload_mapping, "email", "userEmail"), "email")
    tenant_id = _normalize_str(_extract(payload_mapping, "tenantId", "tenant_id"), "tenant_id")

    verified_at_raw = _extract(payload_mapping, "verifiedAt", "verified_at", "timestamp")
    if verified_at_raw is None:
        raise SchemaValidationError("Missing verified_at timestamp")
    try:
        verified_at = int(verified_at_raw)
    except (TypeError, ValueError) as exc:
        raise SchemaValidationError("verified_at must be an integer epoch seconds") from exc

    metadata_payload = payload_mapping.get("metadata")
    if metadata_payload is None:
        metadata = _empty_metadata()
    elif not isinstance(metadata_payload, Mapping):
        raise SchemaValidationError("metadata must be an object when provided")
    else:
        metadata = _wrap_metadata(metadata_payload)

    return EmailVerifiedEvent(
        event_id=event_id,
        auth0_user_id=auth0_user_id,
        email=email,
        tenant_id=tenant_id,
        verified_at=verified_at,
        metadata=metadata,
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


