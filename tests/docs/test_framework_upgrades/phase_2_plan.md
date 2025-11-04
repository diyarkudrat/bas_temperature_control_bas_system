## Phase 2 Patch Plan — Logging Library Focus

### Objective Snapshot
- Lift `logging_lib` unit coverage to ≥85% (warn threshold) with a clear runway to ≥90%+ in Phase 3.
- Prove deterministic, stateless test harnesses for dispatcher/queue logic while validating roadmap drivers (reliability, observability, security/DLP).
- Establish component-specific coverage reporting and gating hooks so regressions trigger actionable signals.

### Scope & Boundaries
- **In scope:** logging configuration, dispatcher/queue, sampling & redaction helpers, sink adapters, schema/context builders, coverage tooling updates, fixture/docs uplift tied to logging.
- **Out of scope:** API/auth service test work, production code refactors beyond logging library seams, optional chaos/load tests (captured for later phases).

### Work Breakdown
- **Harness & Tooling Foundation**
  - Create `tests/unit/logging/conftest.py` with deterministic dispatcher fixture, in-memory sink registry, and metrics reset hooks (respects `BAS_DISABLE_PLUGINS=1`).
  - Add logging-focused pytest markers (`@pytest.mark.logging`) and selective plugin opt-ins to keep suites fast.
  - Update `pytest.ini`/`noxfile.py` to surface `unit-logging` session running `pytest tests/unit/logging --cov=logging_lib --cov-fail-under=85` with context=`logging`.
- **Configuration & Manager Tests**
  - Expand `tests/unit/logging/test_config.py` (new) to cover `LoggerManager.configure`, `settings`/`dispatcher` lazy init, sink list fallbacks, and stateless reconfiguration assertions.
  - Validate omit rules for optional sinks via `.coveragerc` updates (`logging_lib/sinks/gcl_api.py`).
- **Dispatcher & Queue Coverage**
  - Introduce `test_dispatcher_queue.py` targeting batch flush, retry backoff, drop handling, and queue length enforcement using synchronous harness.
  - Assert metrics/logging side-effects for drop events (`RingBufferQueue.emit_drop_event`) and capability toggles required for observability roadmap items.
- **Sampling & Redaction Scenarios**
  - Build parameterized suite for `logging_lib/sampling.py` verifying deterministic token behavior, sticky fields, fallback when context missing, and failure branches.
  - Cover `logging_lib/redaction.py` registry builder for includes/excludes, truncation length, strict-mode errors, and DLP-sensitive keys.
- **Sink Behavior**
  - Add tests for `StdoutSink`, `InMemorySink`, and stubbed `GCLSink` using module patching to assert payload transformation and failure handling paths.
  - Verify metric increments & trace hooks triggered when sinks error (roadmap observability alignment).
- **Schema & Context Validation**
  - Test `build_log_record` ensuring payload size enforcement, correlation IDs, truncation markers, and contextvars reset between runs.
  - Cover context propagation helpers to guarantee statelessness across xdist runs.
- **Documentation & Knowledge Share**
  - Draft `tests/docs/test_framework_upgrades/logging_library_testing.md` (stub in Phase 2 with usage patterns, to be completed in Phase 5).
  - Log mentoring/retro notes for Phase 2 deliverables into portfolio packet.

### Dependencies & Sequencing
- Complete Phase 1 fixture split groundwork (lightweight `tests/unit/conftest.py`) before enabling logging-specific fixtures.
- Ensure `.coveragerc` and `pytest.ini` changes from Phase 0 are merged to avoid merge conflicts; coordinate with CI team for coverage job skeleton.
- Align with platform team on optional dependency mocks (e.g., Google Cloud logging) to avoid build failures.

### Risk Mitigations
- **Global queue state leaks:** enforce fixture teardown that resets dispatcher singletons; add regression test verifying fresh state per test.
- **Slow/flaky tests:** prefer synchronous dispatcher harness and deterministic random seeds; fail fast with `--maxfail=1` during early iterations.
- **Optional dependency gaps:** mark GCL sink tests with `@pytest.mark.optional_dep` and skip gracefully when libs unavailable.
- **Coverage regression noise:** pin `coverage.py`/`pytest-cov` versions and compare JSON outputs when adjusting omit/include lists.

### Validation & Exit Criteria
- CI `unit-logging` job executes in <4 minutes locally and in CI with coverage report emitted to `coverage/logging.xml` + JSON artifact.
- Coverage for `logging_lib` meets ≥85% fail-under with documented exceptions (recorded in `coverage_exceptions.md`, including owner + remediation date).
- Dispatcher, redaction, and sink tests demonstrate roadmap-aligned behaviors (reliability, observability, security) with assertions on metrics/logging payloads.
- Phase review captures lessons learned + updates roadmap alignment checklist.

### Deliverables
- Updated fixtures/tooling (`tests/unit/logging/conftest.py`, `noxfile.py`, `.coveragerc`, `pytest.ini`).
- New/expanded unit test modules under `tests/unit/logging/` covering configuration, dispatcher, sampling/redaction, sinks, and schema.
- CI configuration snippet/documentation for `unit-logging` job.
- Documentation stub `logging_library_testing.md` and portfolio notes.

