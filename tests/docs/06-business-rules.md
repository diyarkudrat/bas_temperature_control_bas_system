# Business Rules

## Purpose

Centralize domain rules to ensure consistent enforcement across tests and implementations.

## Location

- `tests/utils/business_rules.py`

## Typical Rules

- Password policy and credential validation
- Session limits, timeouts, and fingerprint integrity
- Tenant isolation for multi-tenant data
- Audit trail requirements for sensitive operations

## Usage Pattern

```python
from tests.utils.business_rules import BusinessRules

rules = BusinessRules()
result = rules.password_policy_check("MySecurePass123!")
assert result["valid"], result.get("violations")
```

## Guidance

- Keep rules deterministic and side-effect free
- Return structured results with `valid` and `violations`
- Use in tests and contract validators for consistency


