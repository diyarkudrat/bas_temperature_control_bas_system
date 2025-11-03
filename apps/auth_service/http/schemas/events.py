"""Schema definitions for Auth0 webhook events handled by auth-service."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, MutableMapping

from .base import BaseSchema, SchemaValidationError, _ensure_email

def _normalize_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise SchemaValidationError(f"Field '{field}' must be a string")
    normalized = value.strip()
    if not normalized:
        raise SchemaValidationError(f"Field '{field}' is required")
    return normalized



def _extract(payload: Mapping[str, Any] | MutableMapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in payload:
            return payload[name]
    return None


@dataclass(slots=True)
class EmailVerifiedEvent(BaseSchema):
    event_id: str
    auth0_user_id: str
    email: str
    tenant_id: str
    verified_at: int
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def context_claims(self) -> Mapping[str, str]:
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "auth0_user_id": self.auth0_user_id,
        }

    def to_forward_payload(self) -> Mapping[str, Any]:
        payload = self.to_dict()
        return payload


def parse_email_verified_event(payload: Mapping[str, Any] | MutableMapping[str, Any]) -> EmailVerifiedEvent:
    if not isinstance(payload, Mapping):
        raise SchemaValidationError("Webhook payload must be an object")

    event_id = _normalize_str(_extract(payload, "eventId", "event_id"), "event_id")
    auth0_user_id = _normalize_str(_extract(payload, "auth0UserId", "auth0_user_id", "userId", "user_id"), "auth0_user_id")
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
    "EmailVerifiedEvent",
    "parse_email_verified_event",
]


