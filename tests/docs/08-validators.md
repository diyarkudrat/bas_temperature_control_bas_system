# Validators (Runtime Contract Enforcement)

## What it is

Validators check at runtime that data and behaviors match your contracts and business rules. They are typically enabled via pytest flags or fixtures.

## Benefits

- Early, precise failures when behaviors drift
- Safer refactors with automated guardrails
- Self-documenting expectations in tests
- Consistent rule enforcement across components

## Simple example

```python
# In tests, provided by a plugin/fixture
def test_user_creation(contract_enforcer, users_store, valid_user):
    # Pre-validate inputs
    contract_enforcer.verify_create(users_store, valid_user)
    # Execute
    assert users_store.create(valid_user)
```


