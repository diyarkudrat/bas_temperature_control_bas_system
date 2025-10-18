"""Protocol base classes for Firestore stores contract testing."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Protocol, TypeVar, Generic
from dataclasses import dataclass
from google.cloud import firestore

# Type variables for generic protocols
T = TypeVar('T')  # Entity type
K = TypeVar('K')  # Key/ID type


@dataclass
class QueryOptions:
    """Options for query operations."""
    limit: int = 100
    offset: Optional[str] = None
    order_by: Optional[str] = None
    order_direction: str = "DESCENDING"
    filters: Optional[Dict[str, Any]] = None
    # Cursor pagination fields used by validator
    start_after: Optional[str] = None
    start_at: Optional[str] = None


@dataclass
class PaginatedResult(Generic[T]):
    """Paginated query result."""
    items: List[T]
    total_count: Optional[int] = None
    has_more: bool = False
    next_offset: Optional[str] = None


@dataclass
class OperationResult(Generic[T]):
    """Result of a database operation."""
    success: bool
    data: Optional[T] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


class BaseRepositoryProtocol(Protocol[T, K]):
    """Protocol defining the base repository interface."""

    def __init__(self, client: firestore.Client, collection_name: str) -> None:
        """Initialize repository with Firestore client and collection name."""
        ...

    @abstractmethod
    def create(self, entity: T) -> OperationResult[K]:
        """Create a new entity."""
        ...

    @abstractmethod
    def get_by_id(self, entity_id: K) -> OperationResult[T]:
        """Get entity by ID."""
        ...

    @abstractmethod
    def update(self, entity_id: K, updates: Dict[str, Any]) -> OperationResult[T]:
        """Update entity by ID."""
        ...

    @abstractmethod
    def delete(self, entity_id: K) -> OperationResult[bool]:
        """Delete entity by ID."""
        ...

    @abstractmethod
    def query(self, options: QueryOptions) -> PaginatedResult[T]:
        """Query entities with pagination."""
        ...


class AuditStoreProtocol(Protocol):
    """Protocol for audit store operations."""

    def __init__(self, client: firestore.Client) -> None:
        """Initialize with Firestore client."""
        ...

    @abstractmethod
    def log_event(self, event_type: str, user_id: Optional[str] = None, username: Optional[str] = None,
                  ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                  details: Optional[Dict[str, Any]] = None, tenant_id: Optional[str] = None) -> bool:
        """Log an audit event."""
        ...

    @abstractmethod
    def log_auth_success(self, username: str, ip_address: str, session_id: str,
                         tenant_id: Optional[str] = None) -> bool:
        """Log successful authentication."""
        ...

    @abstractmethod
    def log_auth_failure(self, username: str, ip_address: str, failure_reason: str,
                         tenant_id: Optional[str] = None) -> bool:
        """Log failed authentication."""
        ...

    @abstractmethod
    def log_session_creation(self, username: str, session_id: str, ip_address: str,
                             tenant_id: Optional[str] = None) -> bool:
        """Log session creation."""
        ...

    @abstractmethod
    def log_session_destruction(self, session_id: str, username: Optional[str] = None,
                                ip_address: Optional[str] = None, tenant_id: Optional[str] = None) -> bool:
        """Log session destruction."""
        ...

    @abstractmethod
    def log_permission_denied(self, username: Optional[str] = None, user_id: Optional[str] = None,
                              ip_address: Optional[str] = None, resource: Optional[str] = None,
                              tenant_id: Optional[str] = None, reason: str = "INSUFFICIENT_PERMISSIONS") -> bool:
        """Log permission denied event."""
        ...

    @abstractmethod
    def log_tenant_violation(self, username: Optional[str] = None, user_id: Optional[str] = None,
                             ip_address: Optional[str] = None, attempted_tenant: Optional[str] = None,
                             allowed_tenant: Optional[str] = None) -> bool:
        """Log multi-tenant access violation."""
        ...

    @abstractmethod
    def query_events_by_user(self, user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query audit events by user ID."""
        ...

    @abstractmethod
    def query_events_by_type(self, event_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query audit events by event type."""
        ...

    @abstractmethod
    def query_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Query recent audit events."""
        ...

    @abstractmethod
    def query_events_by_tenant(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query audit events by tenant."""
        ...

    @abstractmethod
    def query_events_window(self, start_time_ms: int, end_time_ms: int,
                            event_type: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """Query audit events within a time window."""
        ...


class UsersStoreProtocol(BaseRepositoryProtocol[T, K], Protocol):
    """Protocol for users store operations."""

    def __init__(self, client: firestore.Client) -> None:
        """Initialize with Firestore client."""
        ...

    @abstractmethod
    def get_by_username(self, username: str) -> OperationResult[T]:
        """Get user by username."""
        ...

    @abstractmethod
    def get_by_email(self, email: str) -> OperationResult[T]:
        """Get user by email."""
        ...

    @abstractmethod
    def update_password(self, user_id: K, new_password_hash: str, new_salt: str) -> OperationResult[T]:
        """Update user password."""
        ...

    @abstractmethod
    def update_last_login(self, user_id: K, ip_address: str) -> OperationResult[T]:
        """Update user's last login information."""
        ...

    @abstractmethod
    def deactivate_user(self, user_id: K) -> OperationResult[bool]:
        """Deactivate a user account."""
        ...

    @abstractmethod
    def list_users(self, tenant_id: Optional[str] = None, limit: int = 100) -> List[T]:
        """List users with optional tenant filtering."""
        ...


class SessionsStoreProtocol(BaseRepositoryProtocol[T, K], Protocol):
    """Protocol for sessions store operations."""

    def __init__(self, client: firestore.Client) -> None:
        """Initialize with Firestore client."""
        ...

    @abstractmethod
    def get_by_session_id(self, session_id: str) -> OperationResult[T]:
        """Get session by session ID."""
        ...

    @abstractmethod
    def get_active_sessions_by_user(self, user_id: K) -> List[T]:
        """Get active sessions for a user."""
        ...

    @abstractmethod
    def invalidate_session(self, session_id: str) -> OperationResult[bool]:
        """Invalidate a specific session."""
        ...

    @abstractmethod
    def invalidate_user_sessions(self, user_id: K) -> OperationResult[int]:
        """Invalidate all sessions for a user."""
        ...

    @abstractmethod
    def cleanup_expired_sessions(self) -> OperationResult[int]:
        """Clean up expired sessions."""
        ...

    @abstractmethod
    def extend_session(self, session_id: str, new_expiry: int) -> OperationResult[T]:
        """Extend session expiry time."""
        ...


class DevicesStoreProtocol(BaseRepositoryProtocol[T, K], Protocol):
    """Protocol for devices store operations."""

    def __init__(self, client: firestore.Client) -> None:
        """Initialize with Firestore client."""
        ...

    @abstractmethod
    def get_by_device_id(self, device_id: str) -> OperationResult[T]:
        """Get device by device ID."""
        ...

    @abstractmethod
    def get_by_zone(self, zone_id: str) -> List[T]:
        """Get devices by zone."""
        ...

    @abstractmethod
    def update_device_status(self, device_id: str, status: str, last_seen: Optional[int] = None) -> OperationResult[T]:
        """Update device status."""
        ...

    @abstractmethod
    def register_device(self, device_data: Dict[str, Any]) -> OperationResult[K]:
        """Register a new device."""
        ...

    @abstractmethod
    def unregister_device(self, device_id: str) -> OperationResult[bool]:
        """Unregister a device."""
        ...

    @abstractmethod
    def get_devices_by_status(self, status: str, tenant_id: Optional[str] = None) -> List[T]:
        """Get devices by status with optional tenant filtering."""
        ...


class TelemetryStoreProtocol(BaseRepositoryProtocol[T, K], Protocol):
    """Protocol for telemetry store operations."""

    def __init__(self, client: firestore.Client) -> None:
        """Initialize with Firestore client."""
        ...

    @abstractmethod
    def store_sensor_reading(self, device_id: str, sensor_type: str, value: float, timestamp: Optional[int] = None) -> OperationResult[K]:
        """Store a sensor reading."""
        ...

    @abstractmethod
    def get_readings_by_device(self, device_id: str, sensor_type: Optional[str] = None,
                               start_time: Optional[int] = None, end_time: Optional[int] = None,
                               limit: int = 1000) -> List[T]:
        """Get readings by device with optional filters."""
        ...

    @abstractmethod
    def get_latest_reading(self, device_id: str, sensor_type: str) -> OperationResult[T]:
        """Get latest reading for a device sensor."""
        ...

    @abstractmethod
    def aggregate_readings(self, device_id: str, sensor_type: str, start_time: int, end_time: int,
                           aggregation: str = "avg") -> OperationResult[Dict[str, Any]]:
        """Aggregate readings over a time period."""
        ...

    @abstractmethod
    def cleanup_old_readings(self, cutoff_time: int) -> OperationResult[int]:
        """Clean up old telemetry readings."""
        ...


class ServiceFactoryProtocol(Protocol):
    """Protocol for service factory operations."""

    def __init__(self, client: firestore.Client) -> None:
        """Initialize with Firestore client."""
        ...

    @abstractmethod
    def get_users_repository(self) -> UsersStoreProtocol:
        """Get users repository instance."""
        ...

    @abstractmethod
    def get_sessions_repository(self) -> SessionsStoreProtocol:
        """Get sessions repository instance."""
        ...

    @abstractmethod
    def get_devices_repository(self) -> DevicesStoreProtocol:
        """Get devices repository instance."""
        ...

    @abstractmethod
    def get_telemetry_repository(self) -> TelemetryStoreProtocol:
        """Get telemetry repository instance."""
        ...

    @abstractmethod
    def get_audit_store(self) -> AuditStoreProtocol:
        """Get audit store instance."""
        ...