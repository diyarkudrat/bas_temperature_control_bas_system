# Test Framework Upgrade Plan — API Service, Auth Service, Logging Library

## Executive Summary (Portfolio View)
- **Current state:** fragmented fixtures, legacy-weighted coverage (~55–60% across API/auth/logging), and no CI gating.
- **Goal:** lift API, auth, and logging components to ≥90% unit coverage with documented exceptions while validating reliability and security behaviors (health checks, JWT validation, redaction).
- **Timeline:** seven-week phased rollout with governance checkpoints, ADRs, and knowledge-sharing milestones.
- **Impact:** expect 40% faster unit feedback loops, ≥50% fewer flaky reruns, and auditable proof of stateless factories and observability ready for hiring-manager review.
- **Ownership:** end-to-end design and execution led by me, including roadmap alignment, tooling upgrades, and stakeholder communication.

## 1. Outcomes & Success Criteria
- Achieve and enforce ≥90% line coverage for `apps/api`, `apps/auth_service`, and `logging_lib` by the end of Phase 4, while surfacing architecture, reliability, and security regressions called out in `docs/SYSTEM_IMPROVEMENTS.md`. Treat 90% as the default unit-test baseline, with explicitly documented exceptions for low-signal code and higher targets for critical flows.
- Modernize the pytest-based framework so API and auth services are stateless and testable via explicit factories (no module-level singletons), supporting the roadmap’s “Adopt Stateless Deployment Model”.
- Ship fast, reliable unit suites (≤4 min wall-clock on CI runners) with deterministic seeds and hermetic dependencies so chaos/load testing and observability upgrades can layer on with confidence.
- Provide CI coverage gating, per-component dashboards, and actionable failure output to keep coverage from regressing and to document coverage deltas for the personal learning portfolio.
- Explicitly verify roadmap-critical behaviors: health/readiness endpoints, observability hooks, security hardening (JWT validation, redaction), and durable fallbacks for rate limiting/idempotency stores.
- Track complementary quality metrics (runtime, flaky reruns, escaped defects) to show hiring managers the tangible reliability gains alongside coverage.

## 2. Scope & Non-Goals
- **In scope:**
  - Unit-level suites plus focused service-layer integration seams (Flask middleware, service bootstrap, logging dispatcher) that validate roadmap improvements (stateless factories, holistic health checks, observability hooks, modular middleware).
  - Pytest plugins/fixtures, coverage tooling, and developer workflow updates that enable architectural refactors (modular middleware, domain-centric packages).
- **Out of scope (captured for later phases):** Long-running chaos/load tests, full contract rewrites, infrastructure provisioning (Docker/Helm), and mutation testing—these remain stretch goals once core coverage and fixtures stabilize.
- **Target components:**
  - API service (`apps/api`): bootstrap, HTTP layer, middleware, clients, service wiring, readiness endpoints, security headers.
  - Auth service (`apps/auth_service`): Flask app factory, runtime bootstrap, service token plumbing, readiness endpoints, replay protection.
  - Logging library (`logging_lib`): configuration, logger manager, dispatcher/queue, sinks, sampling/redaction helpers supporting DLP and observability requirements.

## 3. Current State Assessment
### 3.1 Repository Layout & Fixtures
- Tests live under `tests/`; the desired layered layout (per `tests/README.md`) is partially in place, but many suites are still under legacy folders (`tests/unit/auth`, `tests/unit/http`).
- `tests/conftest.py` is a monolith configuring plugins, Firestore contract validators, and legacy path injection; it enforces heavy imports even for lightweight unit tests.
- Auth fixtures are extensive (see `tests/unit/auth/`), but API-specific helpers and logging doubles are sparse. Logging coverage currently relies on a single file `tests/unit/logging/test_phase4_runtime.py`.

### 3.2 Coverage Baseline (observed)
- `htmlcov/` exists but reflects historical runs; coverage is not enforced in CI and appears focused on the legacy `bas_server` entrypoint.
- API service coverage is effectively limited to `tests/unit/api/test_device_credentials_service.py`; HTTP routes and middleware under `apps/api/http` are untested in the new service context.
- Auth domain logic is covered, but the standalone `apps/auth_service` bootstrap, service-token loading, and request hooks lack unit coverage.
- Logging library tests only exercise configuration/redaction happy paths; dispatcher concurrency, queue drops, sink fallbacks, and sampling edge cases remain untested.

### 3.3 Tooling Gaps
- `pytest.ini` duplicates `addopts` blocks and points coverage at `server/`, which no longer exists for API/auth services.
- No `.coveragerc` to define component-specific include/exclude rules, nor coverage contexts aligned to roadmap themes (architecture, reliability, security).
- CI scripts (per `scripts/start_backend.sh` etc.) do not run targeted coverage suites; there is no fail-under guard or reporting that ties into roadmap metrics (health checks, observability).
- Plugins for contract/business-rule validation are always imported, lengthening startup time. Opt-out via `BAS_DISABLE_PLUGINS=1` is manual.
- Statlessness and externalized state requirements are not currently validated by tests, so regressions would go unnoticed.

## 4. Design Goals & Constraints
- Preserve developer ergonomics: tests must run via `pytest` without bespoke harnesses; new fixtures should be discoverable and documented for future learning iterations.
- Keep suites deterministic and offline: all new unit tests must stub network, filesystem, Firestore, Redis,/Auth0 calls so load/chaos tooling can plug in later.
- Provide opt-in contract/business-rule validators without blocking unit development speed.
- Ensure new tests align with the layered structure (application, domains, platform) and roadmap mandates (modular middleware, domain-centric packages).
- Maintain compatibility with macOS (local dev) and Linux (CI runners), Python 3.11 runtime (per `System/pyvenv.cfg`).
- Surface roadmap-driven behavior (health checks, observability, security) via coverage reports tagged by context to showcase personal learning outcomes.

## 5. Alignment with `docs/SYSTEM_IMPROVEMENTS.md`
- **Architecture & Scalability:**
  - Tests will enforce stateless factories (`create_app` patterns) and catch module-level singleton regressions.
  - Middleware and rate limiter suites will verify that durable backends (Redis/Firestore stubs) are wired via configuration, preparing for externalized state toggles.
  - Coverage metrics segmented by module help demonstrate modularization of org flows and domain services.
- **Reliability & Fault Tolerance:**
  - Health check tests will validate downstream dependency probes and circuit breaker behavior.
  - Logging/metrics unit tests ensure observability emitters fire and redaction/sampling protect data even during failures.
  - Retry queue and rate limiter tests provide scaffolding for chaos and load test follow-ups.
- **Code Quality & Readability:**
  - Test layout refactors and fixture documentation align with modular middleware/domain-centric code organization.
  - Coverage and testing conventions set the stage for future linting (`ruff`/`mypy`) and mutation testing adoption.
- **Security & Best Practices:**
  - Auth service tests cover JWT validation, replay protection, and service token policies.
  - Logging redaction suites confirm DLP mandates, providing evidence toward SOC2-ready logging.
- **Portfolio Impact:**
  - Phase summaries and coverage dashboards will feed into ADRs/runbooks demonstrating measurable improvements for the personal learning narrative.

## 5. Framework Upgrades (Leadership & Execution)
### 5.1 Pytest & Coverage Configuration
- Replace duplicated `addopts` in `pytest.ini` with a single block; reference a new `.coveragerc` scoped to `apps/api`, `apps/auth_service`, and `logging_lib`.
- Introduce `coverage/.coveragerc` with component-specific `[run]` and `[report]` sections:
  - Use `source = apps/api, apps/auth_service, logging_lib`.
  - Add omit rules for entrypoint scripts (`apps/api/main.py` CLI guards), generated templates, and optional GCL sink imports (`logging_lib/sinks/gcl_api.py`).
- Configure per-component fail-under thresholds using coverage contexts:
  - `coverage run --context=api` for API-targeted suites, etc.
  - Use `coverage combine` and `coverage json` to surface metrics in CI dashboards.
- Wire `pytest-cov` invocations through task runners:
  - Add `nox` session `tests(unit_api|unit_auth|unit_logging)` to isolate dependencies and ensure fast iteration.
  - Provide `make test-api-unit`, `make test-auth-unit`, `make test-logging-unit` wrappers for developers.
  - Publish a weekly metrics digest (coverage delta, mean runtime, flaky count) to demonstrate leadership visibility.

### 5.2 Fixture & Plugin Strategy
- Split `tests/conftest.py` into layered fragments:
  - `tests/unit/conftest.py`: lightweight defaults, auto-use markers, base fake time fixture.
  - `tests/unit/api/conftest.py`: Flask app factory fixture for `apps/api`, dependency mocks (rate limiter, tenant middleware, auth provider).
  - `tests/unit/auth/conftest.py`: focus on `apps/auth_service`, reuse auth-domain fixtures but avoid global monkeypatch of `bas_server`.
  - `tests/unit/logging/conftest.py`: provide in-memory sink registry, deterministic queue executor, isolated metrics reset.
- Gate heavy plugins via environment flag defaulting to **disabled** for unit suites; document enabling for contract runs.
- Introduce reusable helpers under `tests/utils/`:
  - `flask_client_factory.py`: builds an app with injectable config overrides and asserts that state is reset between calls (statelessness proof).
  - `env.py`: context manager for env var swaps to avoid leaking state across tests.
  - `logging.py`: synchronous dispatcher harness (execute queue drain inline) plus helpers to assert structured metrics output.
  - `healthcheck.py`: utility to emulate downstream dependency failures so readiness tests cover breaker behavior.
  - Capture mentoring notes and code-review summaries as part of the personal project log to highlight leadership.

### 5.3 Developer Workflow Updates
- Add `pre-commit` hooks (optional but recommended) to run `pytest -m unit --maxfail=1 --cov-report=term` on staged modules.
- Provide documentation updates in `tests/docs/`:
  - “Writing API service tests” playbook (fixtures, patterns, sample asserts, stateless expectations).
  - “Logging library testing” guide covering concurrency, queue flushing, metrics assertions, and DLP compliance checks.
  - “Health & Observability tests” mini-guide tying readiness probes and structured logging assertions back to the roadmap.
- Update `tests/docs/12-test-commands.md` with new `nox`/`make` targets and coverage expectations.

### 5.4 CI Integration
- Extend CI pipeline (GitHub Actions or internal runner) with matrix jobs:
  - `unit-api`: `pytest tests/unit/api tests/unit/http --cov=apps/api --cov-report=xml:coverage/api.xml --cov-fail-under=90`.
  - `unit-auth`: analogous with `apps/auth_service`.
  - `unit-logging`: `pytest tests/unit/logging --cov=logging_lib --cov-fail-under=90`.
- Publish coverage summaries as build artifacts and upload to centralized dashboard (Codecov/Sonar). Export machine-readable JSON for regression detection.
- Add soft guard in early phases (warn when <85%) and flip to hard fail in Phase 4, with contextual badges (architecture/reliability/security) for the learning dashboard.
- Cache `.pytest_cache` and dependency wheels between runs to keep job <5 minutes.
- Publish health-check simulation results as part of CI artifacts to illustrate readiness behavior.

## 6. Coverage Strategy by Component
### 6.1 API Service (`apps/api`)
- **Bootstrap & Config (`apps/api/main.py`, `bootstrap.py`):**
  - Add tests that exercise `_build_auth_provider` branches (auth0, mock, deny-all) using patched env/config and confirm no module-level singletons leak between app instances.
  - Cover `init_auth`, `init_firestore`, `init_tenant` flows by injecting fake configs and verifying state on the Flask app, including toggles for durable stores (Redis/Firestore) to align with externalized state goals.
  - Validate error handling paths (missing auth0 config, Firestore failures) with `pytest.raises`, ensuring circuit-breaker logging is triggered.
- **HTTP Layer (`apps/api/http/*`):**
  - Use Flask test client fixture to cover auth routes, health endpoints (readiness + liveness), org flows, versioning header injection, and security headers.
  - Add middleware tests for rate limiting (`rate_limit.py`), idempotency store, security headers, tenant context—assert order of operations, durable backend fallback, and failure responses requested in the roadmap.
  - Parameterize tests around headers (tenant missing, user agent variations) to exercise logging context and observability metadata.
- **Clients & Services:**
  - Mock outbound HTTP (AuthServiceClient) using `responses` or built-in `requests_mock` to validate retries, metrics increments, breaker activation, and error translation.
  - Expand `DeviceCredentialService` tests to cover rotation window math, metadata defaults, secret manager fallbacks, failure scenarios, and logging redaction of secrets.
- **Utilities & Observability:**
  - Add property-style tests for version negotiation in `http/versioning.py` and schema validations in `http/schemas/*`.
  - Assert structured logging payloads include trace/request identifiers per roadmap DLP/observability guidance.
- **Target Coverage:** 90%+ line coverage, with branch coverage on auth provider selection, middleware fallback logic, and health-check failure states.

### 6.2 Auth Service (`apps/auth_service`)
- **Application Factory (`create_app`, `bootstrap_runtime`):**
  - Build parametric tests that instantiate the Flask app with stubbed configs; assert hooks, blueprints, error handlers, and stateless context initialization are registered.
  - Verify exception handling when configuration files are missing/corrupt (`ServiceConfigurationError`) and ensure failures propagate meaningful health-check responses.
- **Service Tokens & Security (`_build_service_token_settings`):**
  - Use env fixtures to cover success, missing keyset, mismatched issuers, replay cache backend selection, and required scopes aligned with “Service-to-Service Policy”.
  - Validate `ServiceTokenSettings` dataclass inputs (audience, subjects, required scopes) with boundary cases (empty env, CSV parsing).
- **Runtime Dependencies:**
  - Mock `load_service_keyset_from_env`, `load_replay_cache_from_env`, `CircuitBreaker` to assert logging side-effects, replay protection, and rate limiter wiring.
  - Test `register_healthcheck` and request hooks (context logging, metrics counters) using Flask request contexts, ensuring observability context attaches request IDs and tenant info.
- **Service Layer (`apps/auth_service/services/*`):**
  - Add tests for email verification, invite service token expiration, Auth0 management client request shaping (HTTP verbs, endpoints, error decoding) with redacted logging of sensitive payloads.
  - Use fake HTTP session objects to ensure retries and error classification behave as expected, including circuit breaker transitions.
- **Target Coverage:** ≥92% line coverage, branch emphasis on token error handling, configuration fallbacks, and security logging.

### 6.3 Logging Library (`logging_lib`)
- **Configuration & Manager:**
  - Cover `LoggerManager.configure`, ensuring sink selection, queue sizing, redactor setup, and metrics reset; test fallback to stdout when sinks list empty.
  - Exercise lazy initialization paths for `dispatcher` and `settings` properties and confirm stateless reconfiguration between tests.
- **Dispatcher & Queue:**
  - Create synchronous dispatcher fixture to test batch flushing, retry backoff, and drop handling; assert metadata produced by `RingBufferQueue.emit_drop_event` for multiple drops and verify durable retry semantics envisioned for resiliency.
  - Simulate sink failure to ensure retry/backoff logic, metrics increment, and chaos-test hooks succeed.
- **Sampling & Redaction:**
  - Parameterized tests for `should_emit` across levels, sticky fields, deterministic token behavior (already partially covered) and fallback when context missing.
  - Validate `build_registry` denies/includes nested fields, truncation lengths, strict mode errors, and DLP compliance for sensitive keys (password, secrets, tokens).
- **Sinks & Observability:**
  - Test `StdoutSink`, `InMemorySink`, and (conditional) Google Cloud sink stubs by mocking dependencies to ensure payload transformation and ensure metrics/traces emitted when sinks fail.
- **Schema & Context:**
  - Add tests that ensure `build_log_record` enforces payload limits, attaches context, marks truncated payloads, and includes correlation IDs for tracing goals.
- **Target Coverage:** ≥90% line coverage, with explicit tests around concurrency edge cases (e.g., contextvars reset, queue overrun) and observability instrumentation.

## 7. Phased Implementation Plan
| Phase | Duration | Key Deliverables | Coverage Targets | Exit Criteria |
|-------|----------|------------------|------------------|---------------|
| 0. Baseline (Week 0) | 2 days | Coverage audit script, `.coveragerc`, cleaned `pytest.ini`, coverage-exception rubric draft, baseline metrics snapshot | Document current % + note proposed exceptions | Coverage report published, CI job skeleton created, exception rubric reviewed |
| 1. Framework Foundations (Week 1) | 5 days | Fixture split, lightweight conftests, helper utils, docs updates (`tests/docs/test_framework_upgrades/guide.md`), coverage exception register checked into repo, knowledge-share notes | Maintain baseline with documented exceptions | New fixtures adopted by one pilot suite, tests run <2 min locally, exception register linked from docs, mentoring recap logged |
| 2. Logging Library Focus (Week 2) | 5 days | Expanded logging tests, deterministic dispatcher harness, coverage gating at 85% warn, exception review (e.g., optional sinks), mutation test spike | ≥85% logging (default), higher target for critical paths | Logging CI job passes with new tests, fail-under warning enabled, exceptions justified, mutation results recorded |
| 3. API Service Coverage (Weeks 3-4) | 10 days | Route/middleware/unit tests, AuthServiceClient mocks, coverage instrumentation in CI, risk-based coverage plan for adapters, stakeholder demo deck | ≥85% API mid-week, ≥90% by end (with tracked carve-outs) | API CI job enforces 90% fail-under, exceptions reviewed and approved, demo feedback captured |
| 4. Auth Service Coverage (Weeks 5-6) | 10 days | App factory, token settings, service layer tests; unify auth fixtures; security hotspot coverage deeper than 90%; post-mortem simulation dry run | ≥90% auth baseline, ≥95% on security-critical modules | Auth CI job enforces 90% fail-under, shared fixtures stable, high-risk modules documented, dry-run report filed |
| 5. Harden & Document (Week 7) | 3 days | Coverage dashboards, developer docs, regression playbook, pre-commit integration, roadmap alignment summary, coverage exception ADR, executive summary slide | Maintain 90%+ across components (minus approved exceptions) | Coverage trend monitored for 2 successful CI cycles, roadmap alignment doc published, exception ADR merged, slide added to portfolio |

### Coverage Governance Across Phases
- Maintain a living `coverage_exceptions.md` that records rationale, owner, review date, and planned remediation for every module below 90%.
- Pair quantitative coverage gates with qualitative reviews: mutation tests or targeted scenario tests for high-risk modules each phase.
- Require phase exit reviews to confirm exceptions remain justified and that critical modules exceed the baseline (e.g., auth token verification, logging redaction).
- Embed coverage tags (architecture/reliability/security) into reports so roadmap themes stay visible across phases.
- Document learnings per phase in the roadmap alignment summary to reinforce the personal project’s educational goals.
- Track supplemental quality metrics—mean unit test runtime, flaky reruns, escaped defect count—to connect coverage to reliability outcomes.

## 8. Metrics & Reporting
- Nightly coverage pipeline producing JSON + HTML per component and per roadmap theme (architecture, reliability, security), stored under `coverage/` and uploaded to artifact storage.
- Trend dashboard (Grafana/Looker/Codecov or simple markdown summary) with 4-week rolling coverage delta; alert when drop >2% or fail-under breached, annotated with roadmap category.
- Track test runtime, failure rate, flaky test incidents (CI re-runs) to quantify stability improvements and readiness for chaos/load testing; target ≥50% reduction in flaky reruns by Phase 5.
- Document manual run commands and expected runtime in `tests/docs/12-test-commands.md`, including commands grouped by roadmap theme.
- Produce a quarterly portfolio snapshot summarizing coverage, reliability metrics, and key decisions for hiring-manager conversations.

## 9. Risks & Mitigations
- **Global state in Flask apps:** Import-time singletons (`apps/api/main.py`) complicate isolation and violate stateless deployment goals. *Mitigation:* centralize app factory fixture that resets globals via helper functions; use monkeypatch to swap `BASController`/Firestore factories and assert cleanup in teardown.
- **Heavy dependency graph in `tests/conftest.py`:** Could break when splitting fixtures. *Mitigation:* incremental refactor with fallback to legacy imports; run full suite each phase to catch regressions.
- **Coverage gating false negatives:** Build pipeline differences vs local env. *Mitigation:* pin coverage tool versions, run dedicated coverage job on clean virtualenv, compare JSON outputs.
- **Optional dependencies (Google Cloud sink):** Hard to exercise without libs. *Mitigation:* mock modules, mark tests with `@pytest.mark.optional_dep` and skip gracefully when packages missing.
- **Parallel test execution:** Splitting fixtures may expose hidden race conditions. *Mitigation:* enforce deterministic queue draining, leverage `pytest-xdist --dist=loadscope` once suites stabilized, and add stress tests targeting roadmap reliability goals.
- **Roadmap drift:** System improvements evolve; tests may lag updated requirements. *Mitigation:* maintain alignment checklist in documentation and update coverage contexts when roadmap changes.

## 10. Open Questions & Follow-Ups
- Confirm CI environment (GitHub Actions vs internal) to finalize job definitions and caching strategy.
- Decide on adoption of `nox` vs extending existing shell scripts (`scripts/start_backend.sh`) for test orchestration.
- Determine whether to migrate auth-domain tests from `tests/unit/auth` into layered structure during Phase 4 or defer to later phase.
- Evaluate need for contract tests on the new API routes once unit coverage stabilized (possible Phase 8 work).
- Clarify timeline for integrating chaos/load testing so unit coverage can expose the right seams ahead of reliability experiments.
- Identify tooling (e.g., Semgrep/Bandit) integration schedule to tie security tests into coverage contexts.
- Plan cadence for updating portfolio snapshots (monthly vs per phase) to keep hiring collateral fresh.

## 11. Next Steps (Immediate)
- Approve Phase 0 tasks; schedule coverage baseline run using current `pytest` invocation to set reference metrics and capture roadmap-aligned coverage tags.
- Author fixture split RFC (1-pager) to align team before refactoring `conftest`, highlighting stateless deployment and modular middleware requirements.
- Create tracking issues for each phase, including owners, due dates, roadmap mapping, and dependencies on config or secret management.
- Begin drafting developer documentation updates in parallel with fixture refactor to minimize knowledge gaps and tie tests to roadmap outcomes.
- Draft a lightweight alignment checklist that maps each roadmap bullet to planned or existing tests for ongoing validation.
- Assemble baseline portfolio packet: executive summary slide, metrics dashboard screenshot, leadership log template.


## 12. Remaining Work Multi-Phase Execution Plan
- **Phase R1 — Coverage Infrastructure (2 days)**
  - Deliver `.coveragerc` with scoped `source`, `omit`, and context sections plus updated `pytest.ini` `addopts` and `pytest-cov` wiring.
  - Stand up repeatable coverage baseline script that emits HTML + JSON artifacts under `coverage/` with roadmap tags (architecture/reliability/security).
  - Exit criteria: baseline coverage snapshot published, coverage exception register seeded with current carve-outs.
- **Phase R2 — Test Orchestration (2 days)**
  - Add `nox` sessions (`unit_api`, `unit_auth`, `unit_logging`) and lightweight `make` wrappers; document local usage expectations.
  - Confirm CI runner environment, caching strategy, and artifact retention; capture decisions in tracking issue.
  - Exit criteria: engineers can run each suite via `nox`/`make`; CI decision doc approved.
- **Phase R3 — Fixture & Utility Refactor (4 days)**
  - Split monolithic `tests/conftest.py` into layered unit-level conftests with opt-in heavy plugins.
  - Introduce shared helpers in `tests/utils/` (Flask app factory, env context manager, logging dispatcher harness, health-check simulator) and update docs.
  - Exit criteria: pilot suite runs with new fixtures, statelessness assertions in place, legacy fixtures aliased for backward compatibility.
- **Phase R4 — Component Test Expansions (10 days total)**
  - `R4A API (4 days)`: Cover bootstrap paths, middleware ordering, client/service resilience, and observability hooks with ≥90% coverage and documented exceptions.
  - `R4B Auth (3 days)`: Test app factory boot failures, service-token settings, replay cache wiring, and Auth0 client interactions; target ≥92% coverage.
  - `R4C Logging (3 days)`: Exercise dispatcher/queue fallbacks, sink failures, sampling/redaction edges, and schema enforcement; enforce ≥90% coverage.
  - Exit criteria: coverage gates passing locally for each component; risk-based carve-outs reviewed.
- **Phase R5 — CI & Governance Hardening (3 days)**
  - Implement CI matrix jobs with per-component fail-under thresholds (soft 85% → hard 90%) and publish XML/JSON artifacts with roadmap tags.
  - Wire weekly metrics digest capturing coverage deltas, runtime, and flaky reruns; automate alerts for >2% regressions.
  - Exit criteria: CI pipeline blocks sub-threshold coverage; governance dashboard live.
- **Phase R6 — Documentation & Portfolio Enablement (3 days)**
  - Finalize playbooks (`tests/docs/`), update `tests/docs/12-test-commands.md`, publish fixture RFC outcomes, and refresh alignment checklist.
  - Produce portfolio packet (exec summary, metrics trends, leadership log) and schedule cadence for snapshot updates.
  - Exit criteria: documentation merged, portfolio assets delivered, cadence set on team calendar.


