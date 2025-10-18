# Simple Examples: Adding New Tests

## Purpose

Clear, minimal examples for writing unit tests in this repo: structure, fixtures, markers, assertions, and coverage.

## Quick Start

```bash
# 1) Activate the server venv
cd server && source venv/bin/activate && cd ..

# 2) Run the unit suite
python3 -m pytest tests/unit -v

# 3) Run one file / one test
python3 -m pytest tests/unit/auth/test_services.py -v
python3 -m pytest tests/unit/auth/test_services.py::TestAuthServices::test_login_success -v

# 4) Coverage (terminal + HTML)
python3 -m pytest tests \
  --cov=server \
  --cov=src \
  --cov-report=term-missing \
  --cov-report=html -v
open htmlcov/index.html
```

## Minimal Test (Pure Function)

```python
# tests/unit/example/test_math_utils.py
import pytest

from tests.utils.assertions import assert_equals


def add(a: int, b: int) -> int:
    return a + b


def test_add_returns_sum():
    result = add(2, 3)
    assert_equals(result, 5, "2 + 3 should equal 5")
```

## Using Fixtures

```python
# tests/unit/example/test_tempfile_usage.py
import json
import pytest


@pytest.fixture
def sample_payload():
    return {"username": "alice", "role": "operator"}


def test_can_encode_payload(tmp_path, sample_payload):
    path = tmp_path / "payload.json"
    path.write_text(json.dumps(sample_payload))

    loaded = json.loads(path.read_text())
    assert loaded["username"] == "alice"
```

## Test Class + Markers

```python
# tests/unit/example/test_user_service.py
import pytest
from tests.utils.assertions import assert_true, assert_equals

@pytest.mark.unit
@pytest.mark.auth
class TestUserService:
    def test_create_user_validates(self):
        # Arrange
        input_user = {"username": "bob", "password": "MySecurePass123!"}

        # Act (pretend service call)
        created = {"id": "user_123", "username": input_user["username"]}

        # Assert
        assert_true(bool(created["id"]))
        assert_equals(created["username"], "bob")
```

## Optional: Contract Validation In Tests

Enable runtime contract checks when you want stricter shape/business rule validation.

```bash
python3 -m pytest tests --contract-validation -v
python3 -m pytest tests --contract-report -v
```

Pattern inside a test (optional explicit call):

```python
# tests/unit/example/test_with_contracts.py
import pytest
from tests.contracts.firestore import ContractEnforcer

@pytest.mark.contract
class TestContracts:
    def test_sample_contract(self):
        enforcer = ContractEnforcer()
        data = {"user_id": "user_123", "timestamp_ms": 1000}
        # Example: validate required fields (API differs by concrete validator)
        enforcer.enforce_create_contract(data, ["user_id", "timestamp_ms"])  # raises on violation
```

## Naming & Structure

- File name: `test_<component>.py`
- Class name: `Test<Component>`; method: `test_<behavior>`
- Arrange → Act → Assert
- Keep tests small; prefer one focused assertion or a short set of related checks

## Assertions Helpers

```python
from tests.utils.assertions import (
    assert_true, assert_false, assert_equals,
    assert_is_none, assert_is_instance,
)
```
Use these helpers for consistent, readable messages.

## Common Patterns

- Filter tests: `-k login` matches by substring
- Parametrize variants:

```python
import pytest

@pytest.mark.parametrize("password,valid", [
    ("MySecurePass123!", True),
    ("weak", False),
])
def test_password_policy(password, valid):
    is_strong = len(password) >= 12 and any(c for c in password if not c.isalnum())
    assert is_strong is valid
```

## Troubleshooting

- Import errors: ensure venv is active and project root is current directory
- Slow runs: focus by file/test/marker; disable contracts with `-m "not contract"`
- Coverage missing lines: use `--cov-report=term-missing` and open `htmlcov/index.html`

## When To Use Markers

- `@pytest.mark.unit`: unit tests (default in this repo)
- `@pytest.mark.auth`: authentication domain
- `@pytest.mark.contract`: when validating contracts
- `@pytest.mark.no_contract_validation`: skip runtime contract checks in perf-sensitive tests

## Next Steps

- Add a new test file under `tests/unit/<domain>/`
- Reuse fixtures from `tests/fixtures/` where helpful
- Capture shared rules in `tests/utils/business_rules.py`
