

## Design Decisions and Trade-offs

- Contract-first testing vs ad-hoc mocks
  - Decision: Use protocols and runtime validators to define expected behaviors.
  - Trade-off: Slight upfront complexity for long-term reliability and clearer failures.

- Centralized business rules
  - Decision: Implement rules in `tests/utils/business_rules.py` and reuse everywhere.
  - Trade-off: One place to update; requires discipline to avoid re-implementing rules in tests.

- Runtime contract enforcement plugin
  - Decision: Optional wrapper validates inputs/outputs at runtime.
  - Trade-off: Extra overhead when enabled; can be disabled via marker/flag for perf-critical tests.

- Protocol-oriented dependencies
  - Decision: Tests depend on interfaces, not concrete implementations.
  - Trade-off: Requires protocol upkeep; enables easier refactoring and mock replacement.

- CI enforcement
  - Decision: Fail CI on contract/business rule violations.
  - Trade-off: Stricter gatekeeping improves quality; initial iterations may be slower.

## Design Decisions Summary

| ID | Decision | Rationale | Trade-off |
|----|----------|-----------|-----------|
| T1 | Protocol + runtime validators | Precise behavioral specs; clearer failures | Initial complexity and maintenance |
| T2 | Centralized business rules | Single source of truth; consistency | Requires discipline to avoid duplication |
| T3 | Optional runtime enforcement | Catch violations early | Overhead when enabled |
| T4 | Protocol-oriented dependencies | Easier refactors; mock interchangeability | Protocol upkeep required |
| T5 | CI fails on violations | Prevent regressions | Slower early iterations |