"""Firestore service factory stub for API unit tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class FirestoreHealth:
    status: str
    details: Dict[str, Any] = field(default_factory=dict)


class FirestoreStub:
    """Stub providing Firestore factory-like behavior for tests."""

    def __init__(self) -> None:
        """Initialize firestore stub."""

        self.health_checks: list[Dict[str, Any]] = []
        self.audit_requests: list[Dict[str, Any]] = []
        self.health_response = FirestoreHealth(status="healthy")

    # Factory-style interface
    def health_check(self) -> Dict[str, Any]:
        """Health check."""

        payload = {"status": self.health_response.status, "details": self.health_response.details}
        self.health_checks.append(payload)

        return {"status": payload["status"], "details": payload["details"]}

    def get_audit_service(self) -> "FirestoreStub":
        """Get audit service."""

        self.audit_requests.append({})

        return self

    # Audit sink behavior
    def record_event(self, event: Dict[str, Any]) -> None:
        """Record an event."""

        self.audit_requests.append(event)

    def set_health(self, status: str, **details: Any) -> None:
        """Set the health."""

        self.health_response = FirestoreHealth(status=status, details=details)

    def reset(self) -> None:
        """Reset the firestore stub."""
        
        self.health_checks.clear()
        self.audit_requests.clear()
        self.health_response = FirestoreHealth(status="healthy")

