# Fixture Split Outline — Phase 0

## Goals
- Keep pytest startup fast and predictable while enabling ≥90% coverage for `apps/api`, `apps/auth_service`, `adapters`, and `app_platform`.
- Make stateless factories and deterministic fakes the default so every test run starts from a clean slate.
- Defer heavy plugins and contract validators until explicitly requested.

## Proposed Layout
- `tests/unit/conftest.py`
  - Minimal global fixtures (`freeze_time`, `env_swap`, `clear_context`)
  - Automatically disables legacy plugins unless `BAS_ENABLE_CONTRACT_FIXTURES=1`
- `tests/unit/api/conftest.py`
  - `create_api_app()` factory that asserts no global state leakage
  - Fakes for auth provider, rate limiter, tenant loader, and feature toggles
- `tests/unit/auth/conftest.py`
  - `create_auth_app()` factory with injectable config overrides
  - Deterministic service token builders and replay cache doubles
- `tests/unit/adapters/conftest.py`
  - Protocol-based client fakes (HTTP, queue, storage) with retry counters
  - Data shaping helpers that return immutable payloads for easy assertions
- `tests/unit/platform/conftest.py`
  - Shared bootstrap harness verifying headers, tracing IDs, and logging context
  - Feature toggle fixture that resets environment settings per test

## Migration Notes
- Incrementally peel helpers out of `tests/conftest.py` while preserving imports for legacy suites.
- Keep backwards-compatible aliases during Phase 0, then remove once coverage reaches ≥90%.
- Document each new fixture in `tests/docs/fixtures/README.md` and link from component playbooks.

## Open Questions
- Do we need a shared logging dispatcher fake now, or can we reuse existing logging fixtures until the stretch goal?
- Should adapters and platform share a base “protocol registry” fixture, or remain independent to keep test surfaces small?

