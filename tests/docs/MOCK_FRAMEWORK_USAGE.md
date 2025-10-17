# Mock Framework Usage Guide

## Overview

The Mock Framework provides complete mock implementations of Google Cloud Firestore dependencies, allowing unit tests to run without the Google Cloud SDK installed. This eliminates external dependencies and provides faster, more reliable testing.

## Quick Start

### Basic Import Pattern

```python
from tests.unit.firestore.mock import (
    # Models
    MockUser as User,
    MockDevice as Device,
    MockTelemetryRecord as TelemetryRecord,
    
    # Repositories
    UsersRepository,
    DevicesRepository,
    TelemetryRepository,
    
    # Base Classes
    OperationResult,
    QueryOptions,
    PaginatedResult,
    
    # Exceptions
    FirestoreError,
    PermissionError,
    NotFoundError
)
```

### Running Tests

All tests can now run without Google Cloud SDK:

```bash
# Activate virtual environment
source server/venv/bin/activate

# Run all Firestore tests
python -m pytest tests/unit/firestore/ -v

# Run specific test file
python -m pytest tests/unit/firestore/test_models.py -v

# Run specific test
python -m pytest tests/unit/firestore/test_base.py::TestDataClasses::test_query_options_defaults -v
```

## Framework Components

### 1. Mock Models (`mock_models.py`)

Mock implementations of all data models:

- `MockBaseEntity` - Base entity with common fields
- `MockUser` - User authentication data
- `MockSession` - User session data
- `MockDevice` - Device information
- `MockTelemetryRecord` - Telemetry data
- `MockAuditEvent` - Audit log events

**Example:**
```python
from tests.unit.firestore.mock import MockUser as User

user = User(
    username="testuser",
    password_hash="hashed_password",
    salt="salt_value",
    role="operator"
)
```

### 2. Mock Repositories (`mock_*_store.py`)

Mock implementations of all repository classes:

- `MockUsersRepository` - User data access
- `MockSessionsRepository` - Session management
- `MockDevicesRepository` - Device management
- `MockTelemetryRepository` - Telemetry data
- `MockAuditRepository` - Audit logging

**Example:**
```python
from tests.unit.firestore.mock import DevicesRepository
from unittest.mock import Mock

mock_client = Mock()
devices_repo = DevicesRepository(mock_client)

result = devices_repo.create(device)
assert result.success is True
```

### 3. Mock Base Classes (`mock_base.py`)

Core mock classes and utilities:

- `MockOperationResult` - Standardized operation results
- `MockQueryOptions` - Query configuration
- `MockPaginatedResult` - Paginated data results
- `MockFirestoreError` - Error handling

**Example:**
```python
from tests.unit.firestore.mock import OperationResult, QueryOptions

# Create query options
options = QueryOptions(limit=50, order_by='created_at')

# Check operation result
result = OperationResult(success=True, data="test_data")
assert result.success is True
assert result.data == "test_data"
```

### 4. Mock Service Factory (`mock_service_factory.py`)

Factory for creating mock repository instances:

```python
from tests.unit.firestore.mock import FirestoreServiceFactory

factory = FirestoreServiceFactory()
users_repo = factory.get_users_repository()
devices_repo = factory.get_devices_repository()
```

### 5. Mock Utilities (`mock_utils.py`)

Helper functions for test data creation:

```python
from tests.unit.firestore.mock import (
    create_mock_user_data,
    create_mock_device_data,
    create_mock_telemetry_data,
    MOCK_TENANT_ID,
    MOCK_USERNAME
)

user_data = create_mock_user_data()
device_data = create_mock_device_data(tenant_id=MOCK_TENANT_ID)
```

## Migration Guide

### Before (Original Imports)
```python
from server.services.firestore.models import User, Device
from server.services.firestore.users_store import UsersRepository
from server.services.firestore.base import OperationResult
```

### After (Mock Imports)
```python
from tests.unit.firestore.mock import (
    MockUser as User,
    MockDevice as Device,
    UsersRepository,
    OperationResult
)
```

### Key Changes

1. **Import Path**: Change from `server.services.firestore.*` to `tests.unit.firestore.mock`
2. **Model Names**: Use `MockUser as User` pattern for backward compatibility
3. **Repository Names**: Direct import (aliases provided automatically)
4. **Exception Handling**: Use mock exceptions instead of Google Cloud exceptions

## Test Examples

### Testing Model Creation
```python
def test_user_creation():
    user = User(
        username="testuser",
        password_hash="hash123",
        salt="salt456"
    )
    
    assert user.username == "testuser"
    assert user.is_admin == False  # Default role is "operator"
    assert user.is_locked == False
```

### Testing Repository Operations
```python
def test_device_creation():
    mock_client = Mock()
    devices_repo = DevicesRepository(mock_client)
    
    device = Device(
        tenant_id="tenant_123",
        device_id="device_456"
    )
    
    result = devices_repo.create(device)
    assert result.success is True
    assert result.data == "tenant_123_device_456"
```

### Testing Error Handling
```python
def test_permission_error():
    from tests.unit.firestore.mock import MockPermissionDenied, PermissionError
    
    # Simulate permission denied
    error = MockPermissionDenied("Access denied")
    
    with pytest.raises(PermissionError):
        # Your code that should raise PermissionError
        raise PermissionError("Access denied", error)
```

## Advanced Usage

### Custom Mock Data
```python
from tests.unit.firestore.mock import create_mock_user_data

# Create user with custom data
user_data = create_mock_user_data(
    username="custom_user",
    role="admin",
    tenant_id="custom_tenant"
)
```

### Batch Operations
```python
from tests.unit.firestore.mock import create_mock_users_batch

# Create multiple users for testing
users_batch = create_mock_users_batch(count=10)
assert len(users_batch) == 10
```

### Validation Testing
```python
from tests.unit.firestore.mock import validate_mock_username, validate_mock_role

# Test validation functions
assert validate_mock_username("valid_user") == True
assert validate_mock_username("invalid@user") == False
assert validate_mock_role("admin") == True
assert validate_mock_role("invalid role") == False
```

## Constants and Configuration

The framework provides useful constants:

```python
from tests.unit.firestore.mock import (
    MOCK_TENANT_ID,
    MOCK_DEVICE_ID,
    MOCK_USER_ID,
    MOCK_SESSION_ID,
    MOCK_USERNAME,
    MOCK_PASSWORD_HASH,
    MOCK_SALT
)

# Use in tests
user = User(
    user_id=MOCK_USER_ID,
    username=MOCK_USERNAME,
    password_hash=MOCK_PASSWORD_HASH,
    salt=MOCK_SALT
)
```

## Benefits

1. **No External Dependencies**: Tests run without Google Cloud SDK
2. **Faster Execution**: No network calls or heavy dependencies
3. **Better Isolation**: Tests focus purely on business logic
4. **Easier CI/CD**: No need for Google Cloud credentials in test environments
5. **Maintainability**: Clear separation between test mocks and production code

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all imports use the mock framework
2. **Dataclass Issues**: All mock models have proper default values
3. **Inheritance Issues**: Repository classes use proper inheritance hierarchy
4. **Missing Assertions**: Import all required assertion functions

### Validation Checklist

- [ ] All imports use `tests.unit.firestore.mock`
- [ ] No references to `server.services.firestore` in tests
- [ ] All required assertion functions imported
- [ ] Mock models have proper default values
- [ ] Repository classes use correct inheritance

## Contributing

When adding new mock classes:

1. Follow the existing naming conventions (`Mock*` prefix)
2. Provide backward compatibility aliases
3. Include proper type hints
4. Add validation in `__post_init__` methods
5. Update the `__init__.py` file with exports
6. Add tests for the new mock classes

## Version Information

- **Version**: 1.0.0
- **Author**: BAS System Project
- **Last Updated**: January 2025
