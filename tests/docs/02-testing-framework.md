# Testing Framework

## Overview

This framework makes writing tests with pytest straightforward. Tests are grouped by area (auth, firestore, etc.), keep shared fixtures and business rules in one place, and describe expected behavior using interfaces ("contracts"). When needed, you can turn on validators to automatically check those contracts while tests run. The payoff is simpler tests, quicker feedback, and safer refactors.

### Simple example

```python
# A tiny contract (protocol)
from typing import Protocol

class UserStore(Protocol):
    def create(self, user: dict) -> bool: ...

# Mock-based test: use a fast fake instead of a real DB
def test_create_user_with_fake(user_store_fake: UserStore):
    assert user_store_fake.create({"username": "ana", "password": "x"})

# Contract-based test: optionally verify behavior matches the contract
def test_store_obeys_contract(contract_enforcer, user_store_impl: UserStore):
    contract_enforcer.verify_create(user_store_impl, {"username": "ana", "password": "x"})
```

It’s built around two simple ideas:

- Contract-based testing: Define clear interfaces and invariants; optional runtime validators check shape and behavior during tests.
- Mock-based testing: Swap external dependencies for fast, deterministic fakes so each test focuses on the code under test.

Benefits at a glance:

- Consistent structure: tests look and feel the same across domains, easier to find and review
- Faster feedback: mocks and shared fixtures make runs quick; validators catch issues early
- Less flakiness: no network/services by default; deterministic test doubles
- Safer refactors: contracts define stable interfaces; implementations can change without breakage
- Easier onboarding: shared utilities and business rules reduce copy‑paste and confusion

## Design Decisions

Decision | Rationale | Trade-off |
|----------|-----------|-----------|
| Protocol + runtime validators | Precise behavioral specs; clearer failures | Initial complexity and maintenance |
| Centralized business rules | Single source of truth; consistency | Requires discipline to avoid duplication |
| Optional runtime enforcement | Catch violations early | Overhead when enabled |
| Protocol-oriented dependencies | Easier refactors; mock interchangeability | Protocol upkeep required |
| CI fails on violations (future) | Prevent regressions | Deferred initially |