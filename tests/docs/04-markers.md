# Markers

## Available Markers

- `unit` — unit tests (default in this repo)
- `auth` — authentication domain
- `contract` — contract validation tests
- `business_rules` — rule validation tests
- `no_contract_validation` — skip contract runtime checks
- `integration` — reserved for future integration tests
- `performance` — reserved for performance tests

## Usage

```bash
# Run only auth tests
python3 -m pytest tests/ -m auth -v

# Run contract tests
python3 -m pytest tests/ -m contract -v

# Skip contract validation for performance-critical tests
python3 -m pytest tests/ -m "not no_contract_validation" -v
```

## Conventions

- Apply domain markers at class level
- Apply `contract` when behavior/data must match protocols
- Use `no_contract_validation` to bypass runtime checks when needed


