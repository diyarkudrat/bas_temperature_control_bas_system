# Troubleshooting

## Contract Violations

Symptoms:

```
ContractViolationError: Missing required fields: ['event_type']
```

Fix:

1. Provide required fields
2. Verify data types and formats
3. Ensure tenant isolation rules are met

## Business Rule Failures

Symptoms:

```
AssertionError: Business rule violation: ['Invalid user ID format']
```

Fix:

1. Inspect `BusinessRules` result; update test data
2. Review rule spec in Business Rules docs

## Import Errors

Symptoms:

```
ImportError: No module named 'tests.contracts'
```

Fix:

1. Ensure all contract files exist
2. Check Python path and `conftest.py` setup

## Performance Issues

- Use `@pytest.mark.no_contract_validation` for perf-critical tests
- Prefer `function` scope fixtures to avoid leakage
- Use optimized contract mocks and lazy init

## Firestore Timeouts

If Firestore queries hang or take too long, repository methods apply a safe default timeout (~15s) and limit results by default. You can override per-call when supported (e.g., `timeout_s`).

Tips:
- Ensure queries include a limit to avoid unbounded streams.
- For emulator/debug sessions, consider increasing timeouts.
- If timeouts trigger frequently, verify Firestore indexes and filters.