## Phase R3 Patch Plan — Fixture & Utility Refactor

### Objectives
- Decompose the monolithic `tests/conftest.py` into layered, lightweight fixtures aligned to API, Auth, and Logging domains.
- Introduce shared utility modules in `tests/utils/` that enforce stateless Flask factories, environment isolation, logging harnesses, and healthcheck simulations.
- Ensure new fixture structure defaults to fast unit execution while keeping heavy plugins opt-in, in support of the roadmap’s stateless deployment mandate.

### Current Observations
- `tests/conftest.py` auto-imports heavy plugins, Firestore contract validators, and legacy globals for every test run.
- Component suites (API/Auth/Logging) duplicate helper logic for Flask app creation, environment overrides, and logging assertions.
- No centralized helper enforces statelessness between app factory invocations or environment resets.

### Deliverables
1. Layered conftest structure:
   - `tests/unit/conftest.py` with common lightweight fixtures (fake time, baseline app config, deterministic seeds).
   - `tests/unit/api/conftest.py` focusing on API Flask app factory, rate limiter/idempotency mocks, auth provider stubs.
   - `tests/unit/auth/conftest.py` encapsulating Auth service app factory, service token settings, replay cache fakes.
   - `tests/unit/logging/conftest.py` for logging dispatcher harness and metrics reset.
   - Update legacy `tests/conftest.py` to re-export or shim while deprecating heavy auto-use behavior.
2. Utility modules under `tests/utils/`:
   - `flask_app_factory.py` (stateless app builder + assertions).
   - `env.py` (context manager for environment variable overrides).
   - `logging.py` (synchronous dispatcher harness, structured log assertions).
   - `healthcheck.py` (helpers to simulate downstream dependencies and failures).
3. Documentation updates describing fixture layout, migration strategy, and opt-in heavy plugins flag.

### Implementation Steps
1. Design fixture split diagram and add as comment in `tests/docs/test_framework_upgrades/orchestration.md` (or new doc section) for reviewer context.
2. Create utility helper modules with unit tests where appropriate (e.g., tests for env context manager, logging harness) to prove determinism.
3. Introduce `tests/unit/conftest.py` with foundational fixtures:
   - deterministic random seed.
   - `freeze_time` or `fake_time` helper (if existing, relocate).
   - `disable_heavy_plugins` fixture that toggles env var (e.g., `BAS_DISABLE_PLUGINS=1`).
4. For each component subdirectory (`tests/unit/api`, `tests/unit/auth`, `tests/unit/logging`), add conftest customizing fixtures:
   - Compose from utilities; ensure each fixture resets global state post-yield.
   - Wire to stub dependencies (e.g., fake rate limiter, mock Auth provider) while honoring stateless factory requirement.
5. Reduce `tests/conftest.py` to optional plugin wiring and re-export of shared fixtures to maintain backward compatibility; document deprecation timeline.
6. Update affected tests to import new fixtures/utilities if they relied on monolithic helpers.
7. Refresh documentation (`tests/docs/test_framework_upgrades/orchestration.md`, `tests/docs/12-test-commands.md` as needed) to describe new fixture layout and how to opt into heavy plugins.

### Files to Touch
- `tests/conftest.py`
- `tests/unit/conftest.py` (new)
- `tests/unit/api/conftest.py` (new)
- `tests/unit/auth/conftest.py` (new)
- `tests/unit/logging/conftest.py` (new)
- `tests/utils/flask_app_factory.py` (new)
- `tests/utils/env.py` (new)
- `tests/utils/logging.py` (new)
- `tests/utils/healthcheck.py` (new)
- Relevant test files referencing legacy fixtures
- `tests/docs/test_framework_upgrades/orchestration.md` (append fixture architecture notes)
- `tests/docs/test_framework_upgrades/coverage_exceptions.md` (update if temporary carve-outs needed)

### Testing & Validation
- Run `nox -s tests_unit_api -- --maxfail=1` to confirm API fixtures integrate (defer until implementation complete, per guidance).
- Similar targeted runs for Auth and Logging suites.
- Execute utility module self-tests (if added) via `pytest tests/utils`.
- Confirm `pytest tests/unit -k legacy_fixture` passes for suites still relying on compatibility shims.

### Risks & Mitigations
- **Hidden fixture coupling:** introduce incremental migration, keeping old fixtures available until suites fully updated.
- **Performance regressions:** measure startup time pre/post split; ensure heavy plugins remain opt-in via env flag.
- **State leakage:** enforce teardown assertions in new utilities (e.g., verifying no global state persists between runs).

### Exit Criteria Checklist
- [ ] Layered conftest files created with stateless fixture implementations.
- [ ] Shared utilities live under `tests/utils/` with documentation and (where feasible) unit coverage.
- [ ] Legacy `tests/conftest.py` slimmed to compatibility shims and documented deprecation path.
- [ ] Documentation updated to reflect fixture layout and opt-in plugin toggles.
- [ ] Temporary coverage exceptions recorded if any suites degraded during migration.

