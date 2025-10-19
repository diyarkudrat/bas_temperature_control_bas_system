from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime


class AlertSeverity(Enum):
    """Normalized alert severities used across channels and storage."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @classmethod
    def from_string(cls, value: str) -> "AlertSeverity":
        normalized = (value or "").strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Invalid AlertSeverity: {value}")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _utc_from_ms(ms: int) -> str:
    return datetime.utcfromtimestamp(ms / 1000).isoformat() + "Z"


@dataclass(frozen=True)
class Alert:
    """
    Canonical alert model for transport-agnostic alerting.
    Designed for validation and easy serialization.
    """
    message: str
    severity: AlertSeverity

    # Targeting (optional; producer decides delivery path)
    sms_to: List[str] = field(default_factory=list)
    email_to: List[str] = field(default_factory=list)
    subject: Optional[str] = None  # used for email

    # Correlation and context
    tenant_id: Optional[str] = None
    device_id: Optional[str] = None
    event_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Timestamps
    timestamp_ms: int = field(default_factory=_now_ms)
    utc_timestamp: str = field(default_factory=lambda: _utc_from_ms(_now_ms()))

    def __post_init__(self):
        if not isinstance(self.severity, AlertSeverity):
            raise ValueError("severity must be an AlertSeverity")
        if not self.message or not isinstance(self.message, str):
            raise ValueError("message is required")
        # Optional sanity: trim overly long messages to keep transports safe
        if len(self.message) > 2000:
            raise ValueError("message too long (max 2000 chars)")
        # Ensure email subject when emailing only (not enforced globally)
        if self.email_to and self.subject is not None and len(self.subject) > 512:
            raise ValueError("subject too long (max 512 chars)")

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize to a plain dict suitable for JSON/Firestore.
        Excludes None and empty collections for compactness.
        """
        data: Dict[str, Any] = {
            "message": self.message,
            "severity": self.severity.value,
            "timestamp_ms": self.timestamp_ms,
            "utc_timestamp": self.utc_timestamp,
        }

        self._add_optional_fields(data)
        
        return data

    def _add_optional_fields(self, data: Dict[str, Any]) -> None:
        """Populate optional fields into the serialized alert payload."""
        if self.sms_to:
            data["sms_to"] = list(self.sms_to)
        if self.email_to:
            data["email_to"] = list(self.email_to)
        if self.subject is not None:
            data["subject"] = self.subject
        if self.tenant_id is not None:
            data["tenant_id"] = self.tenant_id
        if self.device_id is not None:
            data["device_id"] = self.device_id
        if self.event_type is not None:
            data["event_type"] = self.event_type
        if self.metadata:
            data["metadata"] = dict(self.metadata)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        """
        Deserialize from a plain dict. Validates severity and message.
        """
        if "severity" not in data:
            raise ValueError("severity is required")
        if "message" not in data:
            raise ValueError("message is required")

        timestamp_ms = data.get("timestamp_ms", _now_ms())
        utc_timestamp = data.get("utc_timestamp", _utc_from_ms(timestamp_ms))

        return cls(
            message=data["message"],
            severity=AlertSeverity.from_string(data["severity"]),
            sms_to=list(data.get("sms_to", [])),
            email_to=list(data.get("email_to", [])),
            subject=data.get("subject"),
            tenant_id=data.get("tenant_id"),
            device_id=data.get("device_id"),
            event_type=data.get("event_type"),
            metadata=dict(data.get("metadata", {})),
            timestamp_ms=timestamp_ms,
            utc_timestamp=utc_timestamp,
        )


