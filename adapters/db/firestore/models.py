"""Domain models for Firestore entities."""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import uuid
import re

from app_platform.contracts import DeviceLifecycle, InviteStatus, MemberRole, TenantStatus

@dataclass
class BaseEntity:
    """Base entity with common fields."""

    id: Optional[str] = field(default=None, kw_only=True)
    created_at: Optional[int] = field(default=None, kw_only=True)
    updated_at: Optional[int] = field(default=None, kw_only=True)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entity to dictionary."""

        result = {}
        for key, value in self.__dict__.items():
            if value is not None:
                result[key] = value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Create entity from dictionary."""

        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class User(BaseEntity):
    """User entity."""

    user_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    username: str = ""
    password_hash: str = ""
    salt: str = ""
    role: str = "operator"
    last_login: int = 0
    failed_attempts: int = 0
    locked_until: int = 0
    password_history: List[str] = field(default_factory=list)
    algorithm_params: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate required fields after initialization."""

        if not self.username:
            raise ValueError("username is required")
        if not self.password_hash:
            raise ValueError("password_hash is required")
        if not self.salt:
            raise ValueError("salt is required")
    
    @property
    def is_locked(self) -> bool:
        """Check if user account is locked."""

        if self.locked_until == 0:
            return False

        return datetime.now(timezone.utc).timestamp() * 1000 < self.locked_until
    
    @property
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        
        return self.role.lower() == "admin"
    
    def can_access_tenant(self, tenant_id: str) -> bool:
        """Check if user can access specific tenant."""

        # For now, all users can access all tenants
        # In future, this could be enhanced with tenant-specific permissions
        return True


@dataclass
class Session(BaseEntity):
    """User session entity."""

    session_id: str = ""
    user_id: str = ""
    username: str = ""
    role: str = ""
    created_at: int = 0
    expires_at: int = 0
    last_access: int = 0
    fingerprint: str = ""
    ip_address: str = ""
    user_agent: str = ""
    tenant_id: Optional[str] = None
    
    def __post_init__(self):
        """Validate required fields after initialization."""

        if not self.session_id:
            raise ValueError("session_id is required")
        if not self.user_id:
            raise ValueError("user_id is required")
        if not self.username:
            raise ValueError("username is required")
    
    @property
    def is_expired(self) -> bool:
        """Check if session is expired."""

        return datetime.now(timezone.utc).timestamp() * 1000 >= self.expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if session is valid (not expired)."""
        
        return not self.is_expired
    
    def extend_session(self, additional_seconds: int = 1800) -> None:
        """Extend session expiration time."""

        self.expires_at += additional_seconds * 1000


@dataclass
class AuditEvent(BaseEntity):
    """Audit log event."""

    timestamp_ms: int
    utc_timestamp: str
    event_type: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    tenant_id: Optional[str] = None
    
    def __post_init__(self):
        """Validate required fields after initialization."""

        if not self.event_type:
            raise ValueError("event_type is required")
        if self.timestamp_ms <= 0:
            raise ValueError("timestamp_ms must be positive")


# Factory functions for creating entities from data

def create_user(data: Dict[str, Any]) -> User:
    """Create User from dictionary data."""

    return User.from_dict(data)


def create_session(data: Dict[str, Any]) -> Session:
    """Create Session from dictionary data."""

    return Session.from_dict(data)


def create_audit_event(data: Dict[str, Any]) -> AuditEvent:
    """Create AuditEvent from dictionary data."""

    return AuditEvent.from_dict(data)


def create_device(data: Dict[str, Any]) -> Device:
    """Create Device from dictionary data."""

    return Device.from_dict(data)


# Validation functions

def validate_tenant_id(tenant_id: str) -> bool:
    """Validate tenant ID format."""

    if not tenant_id or not isinstance(tenant_id, str):
        return False

    return len(tenant_id) > 0 and len(tenant_id) <= 100


def validate_device_id(device_id: str) -> bool:
    """Validate device ID format."""

    if not device_id or not isinstance(device_id, str):
        return False

    return len(device_id) > 0 and len(device_id) <= 100


def validate_username(username: str) -> bool:
    """Validate username format."""

    if not username or not isinstance(username, str):
        return False

    # Username should be alphanumeric with underscores/hyphens/dots, allowing unicode
    return re.match(r'^[\w_.-]+$', username, re.UNICODE) is not None and len(username) >= 3 and len(username) <= 50


def validate_role(role: str) -> bool:
    """Validate user role."""

    valid_roles = {"admin", "operator", "read-only", "viewer", "guest", "super_admin", "system_admin", "read_only"}

    return role.lower() in valid_roles


def validate_device_status(status: str) -> bool:
    """Validate device status."""

    valid_statuses = {"active", "disabled", "decommissioned", "inactive", "maintenance", "error", "offline"}

    return status.lower() in valid_statuses


@dataclass
class Device(BaseEntity):
    """Device entity."""

    tenant_id: str
    device_id: str
    display_name: str = ""
    hardware_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    status: str = DeviceLifecycle.ACTIVE.value
    last_seen: int = 0
    credentials_ref: Optional[str] = None
    deleted_at: Optional[int] = None
    added_by_user_id: Optional[str] = None
    added_by_email: Optional[str] = None

    def __post_init__(self):
        """Validate required fields after initialization."""

        if not self.tenant_id or not self.device_id:
            raise ValueError("tenant_id and device_id are required")
        if not isinstance(self.tags, list):
            self.tags = list(self.tags) if self.tags else []

    @property
    def is_online(self) -> bool:
        """Check if device is online (seen within last hour)."""

        if self.last_seen == 0:
            return False

        one_hour_ago = datetime.utcnow().timestamp() * 1000 - 3600000  # 1 hour in ms

        return self.last_seen > one_hour_ago

    @property
    def is_active(self) -> bool:
        """Check if device status is active."""

        return str(self.status).lower() == DeviceLifecycle.ACTIVE.value

    def update_last_seen(self) -> None:
        """Update last seen timestamp to now."""

        self.last_seen = int(datetime.utcnow().timestamp() * 1000)


@dataclass
class Tenant(BaseEntity):
    """Tenant aggregate root."""

    tenant_id: str
    name: str
    status: str = TenantStatus.PROVISIONING.value
    slug: Optional[str] = None
    organization_id: Optional[str] = None
    created_by_user_id: Optional[str] = None
    limits: Dict[str, Any] = field(default_factory=dict)
    settings: Dict[str, Any] = field(default_factory=dict)
    counters: Dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate required fields after initialization."""

        if not self.tenant_id:
            raise ValueError("tenant_id is required")
        if not self.name:
            raise ValueError("tenant name is required")
        if self.status not in {item.value for item in TenantStatus}:
            raise ValueError(f"Unsupported tenant status: {self.status}")


@dataclass
class TenantMember(BaseEntity):
    """Tenant member association."""

    tenant_id: str
    user_id: str
    email: str
    role: str = MemberRole.READ_ONLY.value
    status: str = "pending"
    invited_by: Optional[str] = None
    invited_at: Optional[int] = None
    accepted_at: Optional[int] = None
    auth0_user_id: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate required fields after initialization."""

        if not self.tenant_id:
            raise ValueError("tenant_id is required")
        if not self.user_id:
            raise ValueError("user_id is required")
        if not self.email:
            raise ValueError("email is required")
        if self.role not in {item.value for item in MemberRole}:
            raise ValueError(f"Unsupported member role: {self.role}")


@dataclass
class Invite(BaseEntity):
    """Invite document for onboarding new members."""

    invite_id: str
    tenant_id: str
    email: str
    role: str = MemberRole.READ_ONLY.value
    status: str = InviteStatus.PENDING.value
    token_hash: Optional[str] = None
    issued_at: Optional[int] = None
    expires_at: Optional[int] = None
    invited_by: Optional[str] = None
    redeemed_by: Optional[str] = None
    redeemed_at: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.invite_id:
            raise ValueError("invite_id is required")
        if not self.tenant_id:
            raise ValueError("tenant_id is required")
        if not self.email:
            raise ValueError("email is required")
        if self.role not in {item.value for item in MemberRole}:
            raise ValueError(f"Unsupported invite role: {self.role}")
        if self.status not in {item.value for item in InviteStatus}:
            raise ValueError(f"Unsupported invite status: {self.status}")


@dataclass
class IdempotencyKey(BaseEntity):
    """Idempotency record for write operations."""

    key: str
    request_hash: str
    status: str = "in_progress"
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    tenant_id: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    expires_at: Optional[int] = None

    def __post_init__(self) -> None:
        """Validate required fields after initialization."""

        if not self.key:
            raise ValueError("key is required")
        if not self.request_hash:
            raise ValueError("request_hash is required")


@dataclass
class OutboxEvent(BaseEntity):
    """Durable outbox entry for asynchronous processing."""

    event_id: str
    topic: str
    payload: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    available_at: Optional[int] = None
    retry_count: int = 0
    last_error: Optional[str] = None
    partition: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate required fields after initialization."""

        if not self.event_id:
            raise ValueError("event_id is required")
        if not self.topic:
            raise ValueError("topic is required")
        if self.status not in {"pending", "delivered", "failed"}:
            raise ValueError(f"Unsupported outbox status: {self.status}")


def create_tenant(data: Dict[str, Any]) -> Tenant:
    """Create Tenant from dictionary data."""

    return Tenant.from_dict(data)


def create_tenant_member(data: Dict[str, Any]) -> TenantMember:
    """Create TenantMember from dictionary data."""

    return TenantMember.from_dict(data)


def create_invite(data: Dict[str, Any]) -> Invite:
    """Create Invite from dictionary data."""

    return Invite.from_dict(data)


def create_idempotency_key(data: Dict[str, Any]) -> IdempotencyKey:
    """Create IdempotencyKey from dictionary data."""

    return IdempotencyKey.from_dict(data)


def create_outbox_event(data: Dict[str, Any]) -> OutboxEvent:
    """Create OutboxEvent from dictionary data."""
    
    return OutboxEvent.from_dict(data)
