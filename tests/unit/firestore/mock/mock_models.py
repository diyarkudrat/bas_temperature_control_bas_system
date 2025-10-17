"""Mock data models for Firestore entities."""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
import uuid


@dataclass
class MockBaseEntity:
    """Mock base entity with common fields."""
    id: Optional[str] = None
    created_at: Optional[int] = None
    updated_at: Optional[int] = None
    
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
class MockTelemetryRecord(MockBaseEntity):
    """Mock telemetry data record."""
    tenant_id: str = ""
    device_id: str = ""
    timestamp_ms: int = 0
    utc_timestamp: str = ""
    temp_tenths: int = 0
    setpoint_tenths: int = 0
    deadband_tenths: int = 0
    cool_active: bool = False
    heat_active: bool = False
    state: str = ""
    sensor_ok: bool = True
    
    def __post_init__(self):
        """Validate required fields after initialization."""
        if not self.tenant_id or not self.device_id:
            raise ValueError("tenant_id and device_id are required")
        if self.timestamp_ms <= 0:
            raise ValueError("timestamp_ms must be positive")


@dataclass
class MockUser(MockBaseEntity):
    """Mock user entity."""
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
        import time
        return time.time() * 1000 < self.locked_until
    
    @property
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role.lower() == "admin"
    
    def can_access_tenant(self, tenant_id: str) -> bool:
        """Check if user can access specific tenant."""
        # For now, all users can access all tenants
        return True


@dataclass
class MockSession(MockBaseEntity):
    """Mock user session entity."""
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
        import time
        return time.time() * 1000 >= self.expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if session is valid (not expired)."""
        return not self.is_expired
    
    def extend_session(self, additional_seconds: int = 1800) -> None:
        """Extend session expiration time."""
        self.expires_at += additional_seconds * 1000


@dataclass
class MockAuditEvent(MockBaseEntity):
    """Mock audit log event."""
    timestamp_ms: int = 0
    utc_timestamp: str = ""
    event_type: str = ""
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


@dataclass
class MockDevice(MockBaseEntity):
    """Mock device entity."""
    tenant_id: str = ""
    device_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    last_seen: int = 0
    status: str = "active"
    
    def __post_init__(self):
        """Validate required fields after initialization."""
        if not self.tenant_id or not self.device_id:
            raise ValueError("tenant_id and device_id are required")
    
    @property
    def is_online(self) -> bool:
        """Check if device is online (seen within last hour)."""
        if self.last_seen == 0:
            return False
        
        import time
        one_hour_ago = time.time() * 1000 - 3600000  # 1 hour in ms
        return self.last_seen > one_hour_ago
    
    @property
    def is_active(self) -> bool:
        """Check if device status is active."""
        return self.status.lower() == "active"
    
    def update_last_seen(self) -> None:
        """Update last seen timestamp to now."""
        import time
        self.last_seen = int(time.time() * 1000)


# Factory functions for creating mock entities from data
def create_mock_telemetry_record(data: Dict[str, Any]) -> MockTelemetryRecord:
    """Create MockTelemetryRecord from dictionary data."""
    return MockTelemetryRecord.from_dict(data)


def create_mock_user(data: Dict[str, Any]) -> MockUser:
    """Create MockUser from dictionary data."""
    return MockUser.from_dict(data)


def create_mock_session(data: Dict[str, Any]) -> MockSession:
    """Create MockSession from dictionary data."""
    return MockSession.from_dict(data)


def create_mock_audit_event(data: Dict[str, Any]) -> MockAuditEvent:
    """Create MockAuditEvent from dictionary data."""
    return MockAuditEvent.from_dict(data)


def create_mock_device(data: Dict[str, Any]) -> MockDevice:
    """Create MockDevice from dictionary data."""
    return MockDevice.from_dict(data)


# Mock validation functions
def validate_mock_tenant_id(tenant_id: str) -> bool:
    """Validate tenant ID format."""
    if not tenant_id or not isinstance(tenant_id, str):
        return False
    return len(tenant_id) > 0 and len(tenant_id) <= 100


def validate_mock_device_id(device_id: str) -> bool:
    """Validate device ID format."""
    if not device_id or not isinstance(device_id, str):
        return False
    return len(device_id) > 0 and len(device_id) <= 100


def validate_mock_username(username: str) -> bool:
    """Validate username format."""
    if not username or not isinstance(username, str):
        return False
    import re
    return re.match(r'^[a-zA-Z0-9_-]+$', username) is not None and len(username) >= 3 and len(username) <= 50


def validate_mock_role(role: str) -> bool:
    """Validate user role."""
    valid_roles = {"admin", "operator", "read-only", "viewer"}
    return role.lower() in valid_roles


def validate_mock_device_status(status: str) -> bool:
    """Validate device status."""
    valid_statuses = {"active", "inactive", "maintenance", "error", "offline"}
    return status.lower() in valid_statuses
