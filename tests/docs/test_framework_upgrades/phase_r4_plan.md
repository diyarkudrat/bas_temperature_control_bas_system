# Phase R4 — Component Test Expansions Patch Plan

## Intent & Success Metrics
- **Objective:** Elevate unit coverage for `apps/api`, `apps/auth_service`, and `logging_lib` to ≥90% while exercising roadmap-critical behaviors (stateless factories, resilience, security, observability).
- **Scope:** Add or expand test suites, helper harnesses, and targeted code hardening to close gaps called out in `api-auth-logging-coverage-plan.md` §6 and Phase R4 charter (§12 R4A–R4C).
- **Exit Criteria:**
  - Coverage reports show ≥90% per component (auth ≥92% on security hotspots) with documented carve-outs in `coverage_exceptions.md`.
  - New tests pass under `nox -s unit_api`, `nox -s unit_auth`, and `nox -s unit_logging`, staying <4 min per job.
  - Observability, security, and reliability behaviors validated via assertions/log capture.

## Dependencies & Preparation
- Ensure Phase R3 fixture split landed (`tests/unit/**/conftest.py`, helper factories). Confirm legacy fixtures still importable for regression fallback.
- Verify `.coveragerc`, `pytest.ini`, and `nox` sessions are in place with context tagging (`api`, `auth`, `logging`).
- Baseline metrics captured in `coverage/` for delta comparison.
- Confirm CI job skeletons exist so Phase R4 PRs can wire fail-under thresholds.

## Workstream A — API Service Coverage (R4A, 4 days)
**Goal:** Exercise bootstrap, HTTP layer, middleware, and client/service logic for resilience, statelessness, and observability.

### A1. Bootstrap & Configuration Hardening
- Target modules: `apps/api/bootstrap.py`, `apps/api/main.py`, supporting factories.
- Tasks:
  - Introduce table-driven tests around `_build_auth_provider`, `init_auth`, `init_firestore`, `init_tenant` covering env permutations, failure modes, and stateless re-instantiation semantics.
  - Add teardown/cleanup utilities in `tests/utils/flask_app_factory.py` (Phase R3 asset) to verify global singletons reset between runs.
  - Assert log messages / structured metadata for failure cases using `caplog` with roadmap tags (`security`, `reliability`).
- Patch plan:
  - Create `tests/unit/api/test_bootstrap.py` with pytest parametrization; leverage `monkeypatch` for env overrides and sentinel stubs for Firestore/Redis.
  - Implement helper assertions (`assert_app_stateless(app_factory)`) in shared utils if missing.
  - Document new fixtures in `tests/docs/test_framework_upgrades/guide.md` during wrap-up.
  - **Status:** Completed via `tests/unit/api/test_bootstrap.py` (stateless factory, auth runtime permutations) and supporting fixtures in `tests/unit/api/conftest.py`.

### A2. HTTP Route & Middleware Exercisers
- Target modules: `apps/api/http/*`, middleware pipeline, rate limiter, tenant context.
- Tasks:
  - Expand Flask client fixtures to cover readiness/liveness endpoints, auth-protected routes, and secure headers (CSP, versioning).
  - Add tests around middleware ordering, ensuring rate limiting and tenant decorators execute before request handlers; simulate backend failures (Redis unavailable) to assert fallback responses/logging.
  - Parameterize header permutations (missing tenant, malformed auth) verifying 401/429 handling and log redaction of sensitive fields.
- Patch plan:
  - New suites under `tests/unit/api/http/` (e.g., `test_health_endpoints.py`, `test_middleware_pipeline.py`).
  - Use deterministic time/uuid fixtures from Phase R3 to assert idempotency keys and trace IDs.
  - Introduce synthetic `FakeRateLimiter` in `tests/utils` if existing stubs insufficient; ensure teardown resets counters.
  - **Status:** Completed through `tests/unit/api/http/test_health_routes.py`, `test_security_headers.py`, and enhanced rate-limit coverage in `tests/unit/api/http/test_rate_limit_middleware.py` (shadow/failure logging, order validation via rate limiter stub).

### A3. Client & Service Resilience
- Target modules: `apps/api/clients/auth_service_client.py`, service objects (e.g., `DeviceCredentialService`).
- Tasks:
  - Mock outbound HTTP with `responses` or in-project stubs to cover retries, breaker activation, and error translation to domain exceptions.
  - Extend device credential tests to cover rotation edge cases, secret fallback, metadata defaults, and logging redaction assertions.
  - Validate metrics/observability increments (e.g., `counter.inc`) via instrumentation spies.
- Patch plan:
  - Add `tests/unit/api/clients/test_auth_service_client.py` capturing success/error paths.
  - Expand existing `test_device_credentials_service.py` with new parametrized cases; ensure coverage of failure branches.
  - Provide `metrics_spy` helper if not present, using context managers to assert call counts.
  - **Status:** Completed with `tests/unit/api/clients/test_auth_service_client.py` (retry/error translation) and expanded `tests/unit/api/test_device_credentials_service.py` (metadata truncation, rotation clamping, failure propagation).

### A4. Verification & Coverage Hooks
- Run `nox -s unit_api -- --cov=apps/api --cov-context=api` and inspect JSON/HTML outputs.
- Update `coverage_exceptions.md` with any remaining low-signal files (e.g., CLI entrypoints) and note remediation plan.
- Capture runtime/coverage deltas and feed into weekly metrics digest.

## Workstream B — Auth Service Coverage (R4B, 3 days)
**Goal:** Stress app factory, service token settings, replay protection, and Auth0 client behaviors with security focus ≥92%.

### B1. Flask App Factory and Bootstrap
- Target modules: `apps/auth_service/app.py`, `bootstrap_runtime.py`.
- Tasks:
  - Create tests ensuring `create_app` registers blueprints, error handlers, request hooks, and remains stateless across invocations.
  - Simulate missing/corrupt config to assert `ServiceConfigurationError` propagation and health-check response shaping.
- Patch plan:
  - New suite `tests/unit/auth/test_app_factory.py` using Phase R3 factory fixture; capture logs for readiness probe behavior.
  - Add helper to assert app teardown clears global registries.
  - **Status:** Completed in `tests/unit/auth_service/test_app_factory.py` (stateless create_app, hook assertions).

### B2. Service Token Settings & Security Policies
- Target modules: `apps/auth_service/security/service_token_settings.py` (or equivalent). 
- Tasks:
  - Parameterize env parsing (CSV scopes, issuers), missing keyset, mismatched audience, replay cache backend selection.
  - Validate dataclass raises when required secrets absent; assert logging redacts secrets.
- Patch plan:
  - Add `tests/unit/auth/test_service_token_settings.py`; use `env` context manager from Phase R3 to avoid leakage.
  - Expand fixtures to supply fake keysets/replay cache stubs.
  - **Status:** Completed in `tests/unit/auth_service/test_service_token_settings.py` (env parsing, failure handling).

### B3. Runtime Dependencies & Auth0 Client
- Target modules: dependency loaders, `Auth0ManagementClient` wrappers.
- Tasks:
  - Mock `load_service_keyset_from_env`, `load_replay_cache_from_env`, `CircuitBreaker` to assert fallback logging, retry wiring, and telemetry.
  - Ensure request hooks attach tenant/request IDs to context and metrics counters increment.
  - Validate Auth0 client builds correct HTTP requests and handles error payload redaction.
- Patch plan:
  - Create `tests/unit/auth/test_runtime_dependencies.py` or integrate into existing suites.
  - Introduce `FakeCircuitBreaker` / instrumentation spy classes in `tests/utils` if necessary.
  - Use `responses` to emulate Auth0 responses and failure states.
  - **Status:** Completed within `tests/unit/auth_service/test_bootstrap_runtime.py` (runtime wiring, disabled Auth0, provisioning failure logging) and supporting stubs.

### B4. Verification & Security Emphasis
- Run `nox -s unit_auth -- --cov=apps/auth_service --cov-context=auth` ensuring fail-under set to 90 (target 92+).
- Document carve-outs (e.g., optional management endpoints) and justification in `coverage_exceptions.md`.
- Capture security-related assertions for roadmap traceability (log redaction, replay protection) in weekly summary.

## Workstream C — Logging Library Coverage (R4C, 3 days)
**Goal:** Validate dispatcher concurrency, sink fallbacks, sampling/redaction edges, structured schema adherence.

### C1. Logger Manager & Configuration
- Target modules: `logging_lib/manager.py`, `settings.py`.
- Tasks:
  - Test `LoggerManager.configure` for sink selection, queue sizing, redactor wiring; ensure reconfiguration resets state.
  - Cover lazy initialization branches for `dispatcher` and `settings` properties.
- Patch plan:
  - Add `tests/unit/logging/test_manager.py` with fixtures to instantiate manager multiple times, asserting no singleton leakage.
  - Use `caplog` to confirm fallback-to-stdout warnings.
  - **Status:** Completed through `tests/unit/logging/test_config.py` (reconfigure, fallback) and new context coverage.

### C2. Dispatcher & Queue Reliability
- Target modules: `logging_lib/dispatcher.py`, `logging_lib/queue.py`.
- Tasks:
  - Build synchronous dispatcher harness (Phase R3 utility) to test batch flushing, retry backoff, drop handling via `RingBufferQueue.emit_drop_event` metadata.
  - Simulate sink failure to assert retry/backoff logic and metrics increments.
- Patch plan:
  - New suite `tests/unit/logging/test_dispatcher.py` leveraging custom `InMemorySink` with failure injection.
  - Add metrics spy coverage for drop events and ensure concurrency contexts reset (`contextvars`).
  - **Status:** Completed via enhanced `tests/unit/logging/test_dispatcher_queue.py` (flush/retry/drop metadata) and `tests/unit/logging/test_context_management.py` (contextvars reset guarantees).

### C3. Sampling, Redaction, and Sinks
- Target modules: `logging_lib/sampling.py`, `logging_lib/redaction.py`, sink implementations.
- Tasks:
  - Parameterize `should_emit` across levels/sticky fields; confirm deterministic token behavior and fallback when context missing.
  - Validate `build_registry` include/deny lists, truncation, strict-mode errors, SOC2-sensitive key redaction.
  - Test sink payload transformation and metrics/traces emission when sinks fail (stdout, in-memory, optional GCL stub with graceful skip).
- Patch plan:
  - Expand or add `tests/unit/logging/test_sampling.py`, `test_redaction.py`, `test_sinks.py`.
  - Use pytest markers (`@pytest.mark.optional_dep`) for GCL sink tests to skip when dependency absent.
  - **Status:** Completed with existing suites (`tests/unit/logging/test_sampling_redaction.py`, `test_sinks.py`) covering sampling/redaction invariants; optional sink handling gated via existing skips.

### C4. Schema & Context Validation
- Target modules: `logging_lib/schema.py`, `context.py`.
- Tasks:
  - Ensure `build_log_record` enforces payload limits, attaches correlation IDs, marks truncated payloads.
  - Test context reset between emits to prevent cross-request leakage.
- Patch plan:
  - Add tests verifying context reset using context manager; assert truncated flag present in log record when payload exceeds limit.
  - **Status:** Completed in `tests/unit/logging/test_context_management.py` (context scope/reset) and `tests/unit/logging/test_schema.py` (payload truncation assertions).

### C5. Verification & Metrics
- Run `nox -s unit_logging -- --cov=logging_lib --cov-context=logging` and confirm runtime <3 min.
- Update coverage dashboards and metrics digest; add mutation test notes if spikes performed.

## Cross-Cutting Quality Gates
- Update `tests/docs/12-test-commands.md` with new or updated commands once suites land.
- Ensure new tests use deterministic random seeds and avoid network/filesystem calls.
- Capture log/metric assertions in documentation for portfolio evidence.
- File tracking issues for any deferred coverage exceptions or flaky test observations.

## Risk Management
- **Singleton regressions:** Re-run suites with `pytest --maxfail=1 --lf` to catch state leakage; enforce teardown checks in factories.
- **Flaky async logging tests:** Run dispatcher suites with `PYTEST_ADDOPTS="-n auto"` dry-run to detect race conditions; pin event loops to synchronous harness when possible.
- **External dependency drift:** Mock external services (Auth0, Firestore, Redis) via fixtures; mark tests as requiring optional deps when unavoidable.
- **Coverage drift:** Compare pre/post coverage JSON; automate alert if drop >2%.

## Validation & Reporting Checklist
- [ ] All new suites referenced in `tests/docs/test_framework_upgrades/phase_r4_plan.md` committed alongside code changes.
- [ ] `coverage_exceptions.md` updated with rationale, owner, review date.
- [ ] CI jobs configured to enforce fail-under 90% (auth security hotspots 92%).
- [ ] Weekly metrics digest annotated with Phase R4 deltas and roadmap tags.
- [ ] Portfolio snapshot updated with before/after coverage and reliability findings.
  - **Status:** Test suites merged; remaining governance tasks tracked in R5/R6 follow-ups (coverage exception register, CI thresholds, reporting cadence).


