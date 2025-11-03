"""Mock utility functions for Firestore operations."""

import time
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime


def generate_mock_user_id() -> str:
    """Generate a mock user ID."""
    return str(uuid.uuid4())


def generate_mock_session_id() -> str:
    """Generate a mock session ID."""
    return f"session_{str(uuid.uuid4())}"


def generate_mock_device_id() -> str:
    """Generate a mock device ID."""
    return f"device_{str(uuid.uuid4())}"


def generate_mock_tenant_id() -> str:
    """Generate a mock tenant ID."""
    return f"tenant_{str(uuid.uuid4())}"


def get_mock_timestamp_ms() -> int:
    """Get current timestamp in milliseconds."""
    return int(time.time() * 1000)


def get_mock_utc_timestamp() -> str:
    """Get current UTC timestamp string."""
    return datetime.utcnow().isoformat() + 'Z'


def create_mock_user_data(username: str = "testuser", **kwargs) -> Dict[str, Any]:
    """Create mock user data."""
    data = {
        'user_id': generate_mock_user_id(),
        'username': username,
        'password_hash': 'mock_hash_123',
        'salt': 'mock_salt_123',
        'role': 'operator',
        'last_login': 0,
        'failed_attempts': 0,
        'locked_until': 0,
        'password_history': [],
        'algorithm_params': {}
    }
    data.update(kwargs)
    return data


def create_mock_session_data(user_id: str, username: str = "testuser", **kwargs) -> Dict[str, Any]:
    """Create mock session data."""
    current_time = get_mock_timestamp_ms()
    data = {
        'session_id': generate_mock_session_id(),
        'user_id': user_id,
        'username': username,
        'role': 'operator',
        'created_at': current_time,
        'expires_at': current_time + 3600000,  # 1 hour from now
        'last_access': current_time,
        'fingerprint': 'mock_fp_123',
        'ip_address': '192.168.1.100',
        'user_agent': 'Mozilla/5.0 (Mock Browser)',
        'tenant_id': None
    }
    data.update(kwargs)
    return data


def create_mock_device_data(tenant_id: str, device_id: str = None, **kwargs) -> Dict[str, Any]:
    """Create mock device data."""
    data = {
        'tenant_id': tenant_id,
        'device_id': device_id or generate_mock_device_id(),
        'metadata': {'location': 'mock_location', 'model': 'mock_model'},
        'last_seen': get_mock_timestamp_ms(),
        'status': 'active'
    }
    data.update(kwargs)
    return data

def create_mock_audit_data(event_type: str, **kwargs) -> Dict[str, Any]:
    """Create mock audit data."""
    data = {
        'timestamp_ms': get_mock_timestamp_ms(),
        'utc_timestamp': get_mock_utc_timestamp(),
        'event_type': event_type,
        'user_id': None,
        'username': None,
        'ip_address': None,
        'user_agent': None,
        'details': {},
        'tenant_id': None
    }
    data.update(kwargs)
    return data


def create_mock_query_options(limit: int = 100, **kwargs) -> Dict[str, Any]:
    """Create mock query options."""
    options = {
        'limit': limit,
        'offset': None,
        'order_by': None,
        'order_direction': 'DESCENDING',
        'filters': None
    }
    options.update(kwargs)
    return options


def create_mock_paginated_result(items: List[Any], **kwargs) -> Dict[str, Any]:
    """Create mock paginated result."""
    result = {
        'items': items,
        'total_count': None,
        'has_more': False,
        'next_offset': None
    }
    result.update(kwargs)
    return result


def create_mock_operation_result(success: bool, **kwargs) -> Dict[str, Any]:
    """Create mock operation result."""
    result = {
        'success': success,
        'data': None,
        'error': None,
        'error_code': None
    }
    result.update(kwargs)
    return result


def mock_time_progression(seconds: int = 3600) -> int:
    """Simulate time progression and return new timestamp."""
    return get_mock_timestamp_ms() + (seconds * 1000)


def create_mock_batch_data(count: int, data_factory_func, **factory_kwargs) -> List[Dict[str, Any]]:
    """Create a batch of mock data using the provided factory function."""
    return [data_factory_func(**factory_kwargs) for _ in range(count)]


def create_mock_users_batch(count: int, username_prefix: str = "user") -> List[Dict[str, Any]]:
    """Create a batch of mock users."""
    return create_mock_batch_data(count, create_mock_user_data, 
                                 username=lambda i: f"{username_prefix}_{i}")


def create_mock_devices_batch(count: int, tenant_id: str, device_prefix: str = "device") -> List[Dict[str, Any]]:
    """Create a batch of mock devices."""
    return create_mock_batch_data(count, create_mock_device_data,
                                 tenant_id=tenant_id,
                                 device_id=lambda i: f"{device_prefix}_{i}")


def create_mock_sessions_batch(count: int, user_id: str, username: str = "testuser") -> List[Dict[str, Any]]:
    """Create a batch of mock sessions."""
    return create_mock_batch_data(count, create_mock_session_data,
                                 user_id=user_id, username=username)


def create_mock_audit_batch(count: int, event_type: str = "LOGIN_SUCCESS") -> List[Dict[str, Any]]:
    """Create a batch of mock audit events."""
    return create_mock_batch_data(count, create_mock_audit_data, event_type=event_type)


def validate_mock_data_structure(data: Dict[str, Any], required_fields: List[str]) -> bool:
    """Validate that mock data has required fields."""
    return all(field in data and data[field] is not None for field in required_fields)


def validate_mock_username(username: str) -> bool:
    """
    Validate mock username format.
    Allows: alphanumeric, underscores, hyphens, dots, unicode characters
    Rejects: empty, whitespace, special characters, spaces, etc.
    """
    if not username or not isinstance(username, str):
        return False
    
    # Check for empty or whitespace-only
    if not username.strip():
        return False
    
    # Check length (reasonable limit)
    if len(username) > 100:
        return False
    
    # Check for invalid characters (allow dots and unicode)
    invalid_chars = ['@', ' ', '\n', '\t', '<', '>', "'", '"', ';', '(', ')', '{', '}', '[', ']', '|', '\\', '/']
    for char in invalid_chars:
        if char in username:
            return False
    
    # Must contain at least one alphanumeric character (including unicode)
    if not any(c.isalnum() for c in username):
        return False
    
    return True


def validate_mock_role(role: str) -> bool:
    """
    Validate mock role format.
    Allows: alphanumeric, underscores, hyphens, unicode characters
    Rejects: empty, whitespace, special characters, spaces, etc.
    """
    if not role or not isinstance(role, str):
        return False
    
    # Check for empty or whitespace-only
    if not role.strip():
        return False
    
    # Check length (reasonable limit)
    if len(role) > 100:
        return False
    
    # Check for invalid characters (allow unicode)
    invalid_chars = [' ', '\n', '\t', '@', '<', '>', "'", '"', ';', '(', ')', '{', '}', '[', ']', '|', '\\', '/']
    for char in invalid_chars:
        if char in role:
            return False
    
    # Must contain at least one alphanumeric character (including unicode)
    if not any(c.isalnum() for c in role):
        return False
    
    return True


def sanitize_mock_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Remove None values from mock data."""
    return {k: v for k, v in data.items() if v is not None}


def merge_mock_data(base_data: Dict[str, Any], override_data: Dict[str, Any]) -> Dict[str, Any]:
    """Merge mock data dictionaries."""
    result = base_data.copy()
    result.update(override_data)
    return result


def create_mock_error_response(error_message: str, error_code: str = "MOCK_ERROR") -> Dict[str, Any]:
    """Create mock error response."""
    return {
        'success': False,
        'error': error_message,
        'error_code': error_code,
        'data': None
    }


def create_mock_success_response(data: Any) -> Dict[str, Any]:
    """Create mock success response."""
    return {
        'success': True,
        'data': data,
        'error': None,
        'error_code': None
    }


# Mock data constants
MOCK_TENANT_ID = "test_e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"
MOCK_DEVICE_ID = "test_device_456"
MOCK_USER_ID = "test_user_789"
MOCK_SESSION_ID = "test_session_abc"

MOCK_USERNAME = "testuser"
MOCK_PASSWORD_HASH = "mock_password_hash"
MOCK_SALT = "mock_salt"

MOCK_IP_ADDRESS = "192.168.1.100"
MOCK_USER_AGENT = "Mozilla/5.0 (Mock Browser)"
MOCK_FINGERPRINT = "mock_fingerprint_123"

MOCK_LOCATION = "Building A, Floor 2"
MOCK_MODEL = "Thermostat V2"

MOCK_EVENT_TYPES = [
    "LOGIN_SUCCESS",
    "LOGIN_FAILED", 
    "LOGOUT",
    "SESSION_EXPIRED",
    "PASSWORD_CHANGED",
    "USER_CREATED",
    "USER_DELETED",
    "DEVICE_ONLINE",
    "DEVICE_OFFLINE",
    "SYSTEM_STARTUP",
    "SYSTEM_SHUTDOWN"
]

MOCK_DEVICE_STATUSES = [
    "active",
    "inactive", 
    "maintenance",
    "error",
    "offline"
]

MOCK_USER_ROLES = [
    "admin",
    "operator",
    "read-only",
    "viewer"
]
