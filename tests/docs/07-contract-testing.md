# Contract Testing

## Concepts

- Protocols define expected interfaces and behaviors
- Runtime validators enforce shape and invariants
- Contract mocks provide fast, validated doubles

## Key Files

- `tests/contracts/base.py` — Protocol definitions
- `tests/contracts/firestore.py` — Validators and enforcers
- `tests/contracts/mocks.py` — Optimized contract mocks

## Enabling Validation

```bash
python3 -m pytest tests/ --contract-validation -v
python3 -m pytest tests/ --contract-report -v
```

## Test Pattern

```python
import pytest

@pytest.mark.contract
def test_user_creation_contract(contract_enforcer, valid_user):
    # Pre-validate business rules
    # contract_enforcer.enforce_create_contract(valid_user, required_fields=["username","password"])  # optional explicit call
    created = users_store.create(valid_user)
    assert created
```