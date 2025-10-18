# Adding Tests Examples

Simple examples for adding tests to the BAS System test framework.

## 📋 Table of Contents

1. [Adding a Single Test](#adding-a-single-test)
2. [Adding a New Test File](#adding-a-new-test-file)
3. [Adding a Complete New Domain](#adding-a-complete-new-domain)
4. [Best Practices](#best-practices)

---

## Adding a Single Test

Add one test method to an existing test file.

### Example: Add test to `test_managers.py`
```python
def test_update_user_role(self, user_manager, created_user):
    """Test updating user role."""
    updated_user = user_manager.update_user_role(created_user.username, "admin")
    assert_equals(updated_user.role, "admin", "Role should be updated")
```

### Run the test:
```bash
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/unit/auth/test_managers.py::TestUserManager::test_update_user_role -v
```

---

## Adding a New Test File

Create a new test file for a component.

### Example: Create `test_notification_service.py`
```python
import pytest
from auth.services import NotificationService
from tests.utils.assertions import assert_true, assert_false

@pytest.mark.auth
@pytest.mark.unit
class TestNotificationService:
    """Test NotificationService."""

    def test_send_email_success(self, auth_config):
        """Test successful email sending."""
        service = NotificationService(auth_config)
        result = service.send_email("user@example.com", "Test", "Body")
        assert_true(result, "Email should be sent")

    def test_send_email_invalid_recipient(self, auth_config):
        """Test email with invalid recipient."""
        service = NotificationService(auth_config)
        result = service.send_email("invalid-email", "Test", "Body")
        assert_false(result, "Email should fail")
```

### Run the tests:
```bash
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/unit/auth/test_notification_service.py -v
```

---

## Adding a Complete New Domain

Add a new domain with fixtures and test files.

### Step 1: Create directory structure
```bash
mkdir -p tests/unit/device
touch tests/unit/device/__init__.py
```

### Step 2: Create fixtures
Create `tests/fixtures/device_fixtures.py`:
```python
import pytest

@pytest.fixture
def sample_device():
    """Provide a sample Device object."""
    return Device(
        device_id="device_001",
        name="Test Thermostat",
        status="online"
    )

@pytest.fixture
def device_manager(temp_db_file):
    """Provide a DeviceManager instance."""
    return DeviceManager(temp_db_file)
```

### Step 3: Update `tests/conftest.py`
Add to imports:
```python
from tests.fixtures.device_fixtures import *
```

Add device marker:
```python
config.addinivalue_line("markers", "device: Device management tests")
```

### Step 4: Create test file
Create `tests/unit/device/test_device_manager.py`:
```python
import pytest
from tests.utils.assertions import assert_equals, assert_true

@pytest.mark.device
@pytest.mark.unit
class TestDeviceManager:
    """Test DeviceManager."""

    def test_add_device(self, device_manager, sample_device):
        """Test adding a device."""
        result = device_manager.add_device(sample_device)
        assert_true(result, "Device should be added")

    def test_get_device(self, device_manager, sample_device):
        """Test getting a device."""
        device_manager.add_device(sample_device)
        device = device_manager.get_device(sample_device.device_id)
        assert_equals(device.name, "Test Thermostat", "Name should match")
```

### Step 5: Run the tests
```bash
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/unit/device/ -v
```

---

## Best Practices

### Test Naming
```python
# Good: Clear and specific
def test_create_user_with_valid_password_succeeds(self):
def test_create_user_with_weak_password_fails(self):

# Bad: Vague
def test_user_creation(self):
def test_validation(self):
```

### Test Structure
```python
def test_example(self):
    """Test what this does."""
    # Arrange - Set up data
    user_manager = UserManager(config)
    
    # Act - Do the thing
    result = user_manager.create_user("testuser", "password", "operator")
    
    # Assert - Check results
    assert_equals(result.username, "testuser", "Username should match")
```

### Use Fixtures
```python
# Good: Use existing fixtures
def test_user_creation(self, user_manager, auth_config):
    pass

# Bad: Complex setup in test
def test_complex_user(self):
    user_manager = UserManager(config)
    # ... lots of setup code
```

### Test Success and Failure
```python
def test_login_success(self, user_manager, sample_user):
    """Test successful login."""
    result = user_manager.authenticate(sample_user.username, "correct_password")
    assert_true(result.success, "Login should succeed")

def test_login_wrong_password(self, user_manager, sample_user):
    """Test login with wrong password."""
    result = user_manager.authenticate(sample_user.username, "wrong_password")
    assert_false(result.success, "Login should fail")
```

### Parametrized Tests
```python
@pytest.mark.parametrize("email,expected", [
    ("valid@email.com", True),
    ("invalid-email", False),
    ("", False)
])
def test_email_validation(self, email, expected):
    result = validate_email(email)
    assert_equals(result, expected)
```

### Exception Testing
```python
def test_invalid_input_raises_error(self):
    with assert_raises(ValueError):
        process_invalid_data("invalid_input")
```

---

## Summary

This guide shows how to add tests in three ways:

1. **Single Test**: Add one method to existing file
2. **New Test File**: Create new file for component
3. **New Domain**: Create complete new domain with fixtures

Remember:
- Use clear test names
- Follow Arrange-Act-Assert pattern
- Test both success and failure cases
- Use fixtures for setup
- Run tests frequently

Happy testing! 🧪