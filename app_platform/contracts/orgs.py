"""Shared organization/domain contracts used across services."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, MutableMapping, Optional


class OrgSignupFeatureFlag(str, Enum):
    """Feature flag keys coordinating rollout between services."""

    ORG_SIGNUP_V2 = "ORG_SIGNUP_V2"
    DEVICE_RBAC_ENFORCEMENT = "DEVICE_RBAC_ENFORCEMENT"


class TenantStatus(str, Enum):
    """Lifecycle status of a tenant."""

    PROVISIONING = "provisioning"
    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETING = "deleting"


class MemberRole(str, Enum):
    """Tenant-scoped roles for members."""

    ADMIN = "admin"
    OPERATOR = "operator"
    READ_ONLY = "read_only"


class InviteStatus(str, Enum):
    """Lifecycle status of an invite token."""

    PENDING = "pending"
    SENT = "sent"
    REDEEMED = "redeemed"
    EXPIRED = "expired"
    REVOKED = "revoked"


class DeviceLifecycle(str, Enum):
    """Device lifecycle states enforced by RBAC."""

    ACTIVE = "active"
    DISABLED = "disabled"
    DECOMMISSIONED = "decommissioned"


@dataclass(frozen=True)
class ProvisioningHeaders:
    """HTTP headers used for provisioning JWT exchange."""

    idempotency_key_header: str = "Idempotency-Key"
    request_jwt_header: str = "X-Request-JWT"
    provisioning_jwt_header: str = "X-Provisioning-JWT"


@dataclass(frozen=True)
class ProvisioningJWTClaims:
    """Standard claims expected in provisioning JWTs."""

    issuer: str = "auth-service"
    audience: str = "api-service"
    subject: str = "org-signup"
    nonce_claim: str = "nonce"
    tenant_claim: str = "tenant"
    jti_claim: str = "jti"


@dataclass(frozen=True)
class ProvisioningClaims:
    """Semantic payload carried in provisioning JWTs."""

    tenant_name: str
    admin_email: str
    tenant_slug: Optional[str] = None
    plan: Optional[str] = None

    def to_claims(self, *, mutable: bool = False) -> Mapping[str, Optional[str]] | MutableMapping[str, Optional[str]]:
        payload: dict[str, Optional[str]] = {
            "tenant_name": self.tenant_name,
            "admin_email": self.admin_email,
        }
        if self.tenant_slug is not None:
            payload["tenant_slug"] = self.tenant_slug
        if self.plan is not None:
            payload["plan"] = self.plan
        return payload if mutable else dict(payload)


PROVISIONING_HEADERS = ProvisioningHeaders()
PROVISIONING_JWT = ProvisioningJWTClaims()


__all__ = [
    "DeviceLifecycle",
    "InviteStatus",
    "MemberRole",
    "OrgSignupFeatureFlag",
    "ProvisioningClaims",
    "ProvisioningHeaders",
    "ProvisioningJWTClaims",
    "PROVISIONING_HEADERS",
    "PROVISIONING_JWT",
    "TenantStatus",
]


