# Style and Conventions

## Test Organization

- One test class per component
- Descriptive test names (what and why)
- Arrange–Act–Assert structure

## Assertions

- Prefer a single focused assertion per test
- Use helpers from `tests/utils/assertions.py` for clarity

## Fixtures

- Keep fixtures small and composable
- Prefer explicit return values over hidden globals
- Choose the narrowest scope needed

## Markers

- Apply domain markers at class-level (e.g., `@pytest.mark.auth`)
- Use `@pytest.mark.contract` when verifying behavior/shape guarantees

## Performance

- Disable runtime contract enforcement when measuring raw performance (`@pytest.mark.no_contract_validation`)


