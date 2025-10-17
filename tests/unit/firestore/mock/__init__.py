"""Mock Firestore framework - central import aliases.

This module provides easy access to all mock classes and functions.
Import from this module to use the mock framework in your tests.
"""

# Mock models
from .mock_models import (
    MockBaseEntity,
    MockTelemetryRecord,
    MockUser,
    MockSession,
    MockAuditEvent,
    MockDevice,
    create_mock_telemetry_record,
    create_mock_user,
    create_mock_session,
    create_mock_audit_event,
    create_mock_device,
    validate_mock_tenant_id,
    validate_mock_device_id,
    validate_mock_username,
    validate_mock_role,
    validate_mock_device_status
)

# Mock base classes
from .mock_base import (
    MockQueryOptions,
    MockPaginatedResult,
    MockOperationResult,
    MockFirestoreError,
    MockPermissionError,
    MockNotFoundError,
    MockValidationError,
    MockBaseRepository,
    MockTenantAwareRepository,
    MockTimestampedRepository,
    MockCacheableRepository,
    MockErrorMappingRegistry,
    # Aliases for backward compatibility
    QueryOptions,
    PaginatedResult,
    OperationResult,
    FirestoreError,
    PermissionError,
    NotFoundError,
    ValidationError,
    BaseRepository,
    TenantAwareRepository,
    TimestampedRepository,
    CacheableRepository,
    ErrorMappingRegistry
)

# Mock exceptions
from .mock_exceptions import (
    MockPermissionDenied,
    MockNotFound,
    MockUnavailable,
    MockDeadlineExceeded,
    MockCancelled,
    MockFailedPrecondition,
    MockAborted,
    MockOutOfRange,
    MockUnimplemented,
    MockInternal,
    MockDataLoss,
    MockUnauthenticated
)

# Mock repositories
from .mock_users_store import (
    MockUsersRepository,
    MockUsersStore  # Backward compatibility alias
)

from .mock_sessions_store import (
    MockSessionsRepository,
    MockSessionsStore  # Backward compatibility alias
)

from .mock_audit_store import (
    MockAuditRepository,
    MockAuditStore  # Backward compatibility alias
)

from .mock_devices_store import (
    MockDevicesRepository,
    MockDevicesStore  # Backward compatibility alias
)

from .mock_telemetry_store import (
    MockTelemetryRepository,
    MockTelemetryStore  # Backward compatibility alias
)

# Mock service factory
from .mock_service_factory import (
    MockFirestoreServiceFactory,
    get_mock_service_factory,
    reset_mock_service_factory,
    get_mock_users_repository,
    get_mock_sessions_repository,
    get_mock_audit_repository,
    get_mock_devices_repository,
    get_mock_telemetry_repository,
    # Backward compatibility aliases
    FirestoreServiceFactory,
    UsersRepository,
    SessionsRepository,
    AuditRepository,
    DevicesRepository,
    TelemetryRepository
)

# Mock utilities
from .mock_utils import (
    generate_mock_user_id,
    generate_mock_session_id,
    generate_mock_device_id,
    generate_mock_tenant_id,
    get_mock_timestamp_ms,
    get_mock_utc_timestamp,
    create_mock_user_data,
    create_mock_session_data,
    create_mock_device_data,
    create_mock_telemetry_data,
    create_mock_audit_data,
    create_mock_query_options,
    create_mock_paginated_result,
    create_mock_operation_result,
    mock_time_progression,
    create_mock_batch_data,
    create_mock_users_batch,
    create_mock_devices_batch,
    create_mock_telemetry_batch,
    create_mock_sessions_batch,
    create_mock_audit_batch,
    validate_mock_data_structure,
    validate_mock_username,
    validate_mock_role,
    sanitize_mock_data,
    merge_mock_data,
    create_mock_error_response,
    create_mock_success_response,
    # Constants
    MOCK_TENANT_ID,
    MOCK_DEVICE_ID,
    MOCK_USER_ID,
    MOCK_SESSION_ID,
    MOCK_USERNAME,
    MOCK_PASSWORD_HASH,
    MOCK_SALT,
    MOCK_IP_ADDRESS,
    MOCK_USER_AGENT,
    MOCK_FINGERPRINT,
    MOCK_LOCATION,
    MOCK_MODEL,
    MOCK_EVENT_TYPES,
    MOCK_DEVICE_STATUSES,
    MOCK_USER_ROLES
)

# Version information
__version__ = "1.0.0"
__author__ = "BAS System Project"

# Export all public symbols
__all__ = [
    # Models
    'MockBaseEntity',
    'MockTelemetryRecord', 
    'MockUser',
    'MockSession',
    'MockAuditEvent',
    'MockDevice',
    'create_mock_telemetry_record',
    'create_mock_user',
    'create_mock_session',
    'create_mock_audit_event',
    'create_mock_device',
    'validate_mock_tenant_id',
    'validate_mock_device_id',
    'validate_mock_username',
    'validate_mock_role',
    'validate_mock_device_status',
    
    # Base classes
    'MockQueryOptions',
    'MockPaginatedResult',
    'MockOperationResult',
    'MockFirestoreError',
    'MockPermissionError',
    'MockNotFoundError',
    'MockValidationError',
    'MockBaseRepository',
    'MockTenantAwareRepository',
    'MockTimestampedRepository',
    'MockCacheableRepository',
    'MockErrorMappingRegistry',
    
    # Backward compatibility aliases
    'QueryOptions',
    'PaginatedResult',
    'OperationResult',
    'FirestoreError',
    'PermissionError',
    'NotFoundError',
    'ValidationError',
    'BaseRepository',
    'TenantAwareRepository',
    'TimestampedRepository',
    'CacheableRepository',
    'ErrorMappingRegistry',
    
    # Exceptions
    'MockPermissionDenied',
    'MockNotFound',
    'MockUnavailable',
    'MockDeadlineExceeded',
    'MockCancelled',
    'MockFailedPrecondition',
    'MockAborted',
    'MockOutOfRange',
    'MockUnimplemented',
    'MockInternal',
    'MockDataLoss',
    'MockUnauthenticated',
    
    # Repositories
    'MockUsersRepository',
    'MockSessionsRepository',
    'MockAuditRepository',
    'MockDevicesRepository',
    'MockTelemetryRepository',
    'MockUsersStore',
    'MockSessionsStore',
    'MockAuditStore',
    'MockDevicesStore',
    'MockTelemetryStore',
    
    # Service factory
    'MockFirestoreServiceFactory',
    'get_mock_service_factory',
    'reset_mock_service_factory',
    'get_mock_users_repository',
    'get_mock_sessions_repository',
    'get_mock_audit_repository',
    'get_mock_devices_repository',
    'get_mock_telemetry_repository',
    'FirestoreServiceFactory',
    'UsersRepository',
    'SessionsRepository',
    'AuditRepository',
    'DevicesRepository',
    'TelemetryRepository',
    
    # Utilities
    'generate_mock_user_id',
    'generate_mock_session_id',
    'generate_mock_device_id',
    'generate_mock_tenant_id',
    'get_mock_timestamp_ms',
    'get_mock_utc_timestamp',
    'create_mock_user_data',
    'create_mock_session_data',
    'create_mock_device_data',
    'create_mock_telemetry_data',
    'create_mock_audit_data',
    'create_mock_query_options',
    'create_mock_paginated_result',
    'create_mock_operation_result',
    'mock_time_progression',
    'create_mock_batch_data',
    'create_mock_users_batch',
    'create_mock_devices_batch',
    'create_mock_telemetry_batch',
    'create_mock_sessions_batch',
    'create_mock_audit_batch',
    'validate_mock_data_structure',
    'validate_mock_username',
    'validate_mock_role',
    'sanitize_mock_data',
    'merge_mock_data',
    'create_mock_error_response',
    'create_mock_success_response',
    
    # Constants
    'MOCK_TENANT_ID',
    'MOCK_DEVICE_ID',
    'MOCK_USER_ID',
    'MOCK_SESSION_ID',
    'MOCK_USERNAME',
    'MOCK_PASSWORD_HASH',
    'MOCK_SALT',
    'MOCK_IP_ADDRESS',
    'MOCK_USER_AGENT',
    'MOCK_FINGERPRINT',
    'MOCK_LOCATION',
    'MOCK_MODEL',
    'MOCK_EVENT_TYPES',
    'MOCK_DEVICE_STATUSES',
    'MOCK_USER_ROLES'
]
