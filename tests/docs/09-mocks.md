# Mocks

## What it is

Mocks are lightweight, in-memory stand‑ins for external systems (e.g., databases, services). They let you run fast, deterministic tests without real network calls or side effects.

## Benefits

- Very fast test execution and no external dependencies
- Deterministic behavior → fewer flaky tests
- Easy to isolate the unit under test
- Works offline; simpler CI setup

## Simple examples

### 1) Ad‑hoc mock with unittest.mock

```python
from unittest.mock import Mock

def test_with_simple_mock():
    client = Mock()
    client.collection.return_value.add.return_value = (None, Mock(id="abc123"))

    # Your code under test uses client.collection("users").add({...})
    # Assert interactions
    client.collection.assert_called_with("users")
```

### 2) Project mock via Service Factory

```python
from tests.unit.firestore.mock import get_mock_service_factory

def test_users_repo_with_factory():
    factory = get_mock_service_factory()
    users = factory.get_users_repository()

    user_id = users.create_user("testuser", "hash", "salt")
    assert user_id
```

### 3) Creating a new mock repository (pattern)

```python
# tests/unit/firestore/mock/mock_widgets_store.py
from typing import Dict, Any
from unittest.mock import Mock
from .mock_base import MockTenantTimestampedRepository, MockOperationResult

class MockWidgetsRepository(MockTenantTimestampedRepository):
    def __init__(self, client: Mock):
        super().__init__(client, 'widgets')
        self.required_fields = ['tenant_id', 'widget_id']

    def create(self, entity) -> MockOperationResult[str]:
        self._validate_required_fields(entity.to_dict(), self.required_fields)
        data = self._enforce_tenant_isolation(entity.tenant_id, entity.to_dict())
        data = self._add_timestamps(data)
        doc_ref = self.collection.document(f"{entity.tenant_id}_{entity.widget_id}")
        doc_ref.set(data)
        return MockOperationResult(success=True, data=doc_ref.id)
```

Tip: Follow existing mocks in `tests/unit/firestore/mock/` (e.g., `mock_users_store.py`) for structure and naming.


