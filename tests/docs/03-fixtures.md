# Fixtures

## Purpose

Fixtures provide reusable, isolated building blocks for tests (configs, sample data, store/service instances). They keep tests small, focused, and fast.

## Locations and Scopes

- `tests/fixtures/` — shared fixtures
- Common scopes: `function` (default), `module`, `session`

## Patterns

### Simple object fixture

```python
import pytest

@pytest.fixture
def sample_user():
    return {
        "username": "testuser",
        "password": "MySecurePass123!",
        "role": "operator",
    }
```

### Resource with teardown

```python
import pytest

@pytest.fixture
def temp_db_file(tmp_path):
    db_path = tmp_path / "test.db"
    yield str(db_path)
    # implicit cleanup by tmp_path
```

### Domain fixture (manager/service)

```python
import pytest
from server.auth.services import UserManager

@pytest.fixture
def user_manager(auth_config):
    return UserManager(auth_config)
```

## Best Practices

- Keep fixtures small and composable
- Prefer domain-specific fixtures per directory
- Avoid hidden global state; return explicit objects
- Use parametrization when exploring variants


