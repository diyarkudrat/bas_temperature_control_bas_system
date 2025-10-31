"""Schema definitions specific to auth-service provisioning flows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, MutableMapping, Optional

from app_platform.contracts import InviteStatus, MemberRole

from .base import (
    BaseSchema,
    SchemaValidationError,
    _ensure_email,
    _ensure_plan,
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
class OrgProvisioningRequest(BaseSchema):
    tenant_name: str
    admin_email: str
    plan: Optional[str] = None
    tenant_slug: Optional[str] = None
    nonce: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class OrgProvisioningResponse(BaseSchema):
    provisioning_jwt: str
    expires_in_seconds: int


def parse_org_provisioning(payload: Mapping[str, Any] | MutableMapping[str, Any]) -> OrgProvisioningRequest:
    tenant_name = _normalize_str(_extract(payload, "tenantName", "tenant_name", "organizationName"), "tenant_name")
    admin_email = _ensure_email(_extract(payload, "adminEmail", "admin_email"), "admin_email")
    plan = _ensure_plan(_extract(payload, "plan", "pricingPlan"))
    tenant_slug = _optional_str(_extract(payload, "tenantSlug", "tenant_slug"))
    nonce = _optional_str(_extract(payload, "nonce", "requestNonce"))
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), Mapping) else {}

    return OrgProvisioningRequest(
        tenant_name=tenant_name,
        admin_email=admin_email,
        plan=plan,
        tenant_slug=tenant_slug,
        nonce=nonce,
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
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class InviteCreateResponse(BaseSchema):
    invite_id: str
    status: InviteStatus
    token: Optional[str] = None


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

    invited_by = _optional_str(_extract(payload, "invitedBy", "invited_by"))
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), Mapping) else {}

    return InviteCreateRequest(
        tenant_id=_normalize_str(tenant_id, "tenant_id"),
        email=email,
        role=role,
        invited_by=invited_by,
        send_email=send_email,
        expires_in_hours=expires_in,
        metadata=metadata,
    )


__all__ = [
    "InviteCreateRequest",
    "InviteCreateResponse",
    "OrgProvisioningRequest",
    "OrgProvisioningResponse",
    "parse_invite_create",
    "parse_org_provisioning",
]


