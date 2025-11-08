# Test Framework Upgrade Plan — API Service, Auth Service, Logging Library

## Executive Summary (Portfolio View)
- **Current state:** fragmented fixtures, uneven coverage (~55–60% across API/auth/logging), and local-only workflows.
- **Immediate goal:** achieve ≥90% unit coverage across `apps/api`, `apps/auth_service`, `adapters`, and `app_platform` using straightforward contract-based and mock-based tests, with exceptions documented but minimal.
- **Timeline:** four lightweight iterations focused on fast local feedback before layering CI automation.
- **Impact:** deliver auditable coverage gains, showcase stateless factories and defensive adapters, and keep the workflow simple enough to demo quickly for hiring conversations.
- **Ownership:** end-to-end design, execution, and documentation led by me; defer GitHub Actions and governance guardrails until the coverage milestone is locked in.

## 1. Outcomes & Success Criteria
- Lift `apps/api`, `apps/auth_service`, `adapters`, and `app_platform` to ≥90% line coverage with contract-based and mock-based unit tests; keep carve-outs explicit and rare.
- Keep fixtures and helpers minimal: stateless factories, deterministic fakes, and focused pytest sessions that run fast on a laptop.
- Validate critical behaviors—JWT validation, readiness/health probes, adapter fallbacks, and platform guards—without introducing heavy plugins or CI orchestration yet.
- Capture before/after coverage evidence and short write-ups for the portfolio, emphasizing design intent, statelessness, and coverage efficacy.

## 2. Scope & Non-Goals
- **In scope:**
  - Focused unit suites that lean on contracts and mocks for API, auth, adapter, and platform code paths; integration seams are exercised only when they unlock coverage for high-risk flows (bootstrap, middleware wiring, adapter fallbacks).
  - Lightweight pytest configuration, stateless fixtures, and helper utilities needed to reach the 90% coverage goal without introducing heavy orchestration or CI dependencies.
- **Out of scope (captured for later phases):** Long-running chaos/load tests, full contract rewrites, infrastructure provisioning (Docker/Helm), and mutation testing—these remain stretch goals once core coverage and fixtures stabilize.
- **Target components:**
  - API service (`apps/api`): bootstrap, HTTP layer, middleware, clients, service wiring, readiness endpoints, security headers.
  - Auth service (`apps/auth_service`): Flask app factory, runtime bootstrap, service token plumbing, readiness endpoints, replay protection.
  - Adapters (`adapters/`): outbound client wrappers, retries, error translation, and data-shaping helpers.
  - Platform layer (`app_platform/`): shared bootstrap, feature toggles, security headers, and observability hooks required across services.

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
- No lightweight `.coveragerc` that scopes measurements to `apps/api`, `apps/auth_service`, `adapters`, and `app_platform` while ignoring legacy paths.
- CI scripts (per `scripts/start_backend.sh` etc.) do not run targeted coverage suites; we will intentionally defer automation until local coverage goals are reached.
- Plugins for contract/business-rule validation are always imported, lengthening startup time. Opt-out via `BAS_DISABLE_PLUGINS=1` is manual; the simplified plan favors explicit opt-in.
- Statlessness and externalized state requirements are not currently validated by tests, so regressions would go unnoticed.

## 4. Design Goals & Constraints
- Preserve developer ergonomics: tests must run via `pytest` without bespoke harnesses; new fixtures should be discoverable and documented for future learning iterations.
- Keep suites deterministic and offline: all new unit tests must stub network, filesystem, Firestore, Redis,/Auth0 calls so load/chaos tooling can plug in later.
- Provide opt-in contract/business-rule validators without blocking unit development speed; default to mocks/fakes for fast feedback.
- Ensure new tests align with the layered structure (application, domains, platform) and roadmap mandates (modular middleware, domain-centric packages).
- Maintain compatibility with macOS (local dev) and Linux (CI runners), Python 3.11 runtime (per `System/pyvenv.cfg`).
- Capture simple coverage reports (terminal + HTML) and short write-ups highlighting roadmap-driven behaviors for portfolio storytelling—no multi-context tagging yet.

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
  - Exercise `_build_auth_provider` branches (auth0, mock, deny-all) via patched environment/config fixtures and assert factories stay stateless between tests.
  - Cover `init_auth`, `init_firestore`, and `init_tenant` flows using deterministic fakes; confirm wiring of feature toggles and fallback logging.
  - Force error paths (missing config, dependency failure) with `pytest.raises` and assert safe responses surfaced through health endpoints.
- **HTTP Layer (`apps/api/http/*`):**
  - Use a simple Flask test client fixture to cover readiness/liveness endpoints, tenant context propagation, and security headers.
  - Validate middleware ordering and fallbacks (rate limiting, idempotency, auth decorators) with mocks instead of live services.
- **Clients & Services:**
  - Mock outbound HTTP/queue clients to validate retries, metrics, and redaction logic without network calls.
- **Coverage Target:** ≥90% line coverage with branch attention on provider selection, middleware fallbacks, and error handling.

### 6.2 Auth Service (`apps/auth_service`)
- **Application Factory (`create_app`, `bootstrap_runtime`):**
  - Instantiate the Flask app with stubbed configs; assert blueprints, hooks, and stateless teardown.
  - Validate failure scenarios (missing secrets, invalid config) and ensure readiness endpoints expose clear diagnostics.
- **Service Tokens & Security (`_build_service_token_settings`):**
  - Parameterize tests around keyset loading, issuer mismatches, replay cache backend toggles, and required scope enforcement.
- **Runtime Dependencies & Services:**
  - Mock Auth0 sessions, replay caches, and breakers to inspect logging, retries, and redaction behavior deterministically.
- **Coverage Target:** ≥90% line coverage, with emphasis on token error handling and guardrails.

### 6.3 Adapters (`adapters/`)
- **Client Wrappers & Retries:**
  - Define protocols/contracts for outbound clients and use in-memory fakes to exercise retry, timeout, and error translation branches.
- **Data Shaping Helpers:**
  - Cover serialization/deserialization helpers with table-driven tests; include failure cases that confirm safe defaults and redactions.
- **Coverage Target:** ≥90% line coverage focused on deterministic handling of success, retry, and terminal failure paths.

### 6.4 Platform Layer (`app_platform/`)
- **Bootstrap & Configuration:**
  - Test feature toggles, environment parsing, and shared app setup using fixtures that reset global state.
- **Security & Observability Hooks:**
  - Use contract-based tests to ensure headers, tracing IDs, and logging context propagate consistently into consuming services.
- **Shared Utilities:**
  - Validate helpers (tenant resolution, request context) with parameterized tests and mocks for external dependencies.
- **Coverage Target:** ≥90% line coverage, proving shared behaviors remain stateless and reusable.

### 6.5 Logging Library (`logging_lib`) – optional stretch
- While not a top-level milestone, maintain existing logging tests and opportunistically expand coverage for dispatcher fallbacks and redaction helpers when it accelerates API/auth/platform work.
- Document any remaining gaps in `coverage_exceptions.md` with owners and follow-up dates once core directories meet the 90% goal.

## 7. Phased Implementation Plan
| Phase | Focus | Key Deliverables | Exit Criteria |
|-------|-------|------------------|---------------|
| 0. Simplify Framework (2 days) | Establish lightweight tooling | Single `.coveragerc` scoped to `apps/api`, `apps/auth_service`, `adapters`, `app_platform`; trimmed `pytest.ini`; baseline coverage snapshot and exception register seeded | Local `pytest --cov` run completes <4 min with documented baseline numbers |
| 1. API Coverage (4 days) | Hit 90%+ in `apps/api` | Contract-focused fixtures, expanded HTTP/middleware/client tests, portfolio notes on stateless factories | Coverage report shows ≥90% with exceptions noted; key auth/middleware behaviors asserted |
| 2. Auth Coverage (4 days) | Hit 90%+ in `apps/auth_service` | Token settings, factory bootstraps, replay protection, and failure-path tests using mocks | Coverage report shows ≥90%; token failure scenarios documented for portfolio |
| 3. Adapters & Platform (5 days) | Hit 90%+ in `adapters/` and `app_platform/` | Protocol contracts, retry behavior tests, platform bootstrap coverage, shared helper documentation | Both directories at ≥90%; shared fixtures prove statelessness |
| 4. Polish & Share (optional, 2 days) | Storytelling and cleanup | Update docs, prepare before/after metrics, identify follow-up work for future enhancements | Portfolio packet updated; backlog for automation/future work captured |

### Coverage Governance Across Phases
- Maintain `tests/docs/test_framework_upgrades/coverage_exceptions.md` as a lightweight ledger for any module below 90%, including rationale and planned remediation.
- Re-run the `pytest --cov` baseline at the end of each phase; update the ledger and capture a short note (win/learn) for the portfolio.
- Keep runtime, coverage %, and notable regressions in a simple markdown log for later automation—no dashboards or gating yet.

## 8. Metrics & Reporting
- Use `python -m pytest tests --cov --cov-config=coverage/.coveragerc --cov-report=term-missing` for fast local snapshots; capture HTML reports only when preparing portfolio updates.
- Log coverage %, runtime, and notable regressions in `docs/metrics/coverage-notes.md` (simple markdown checklist).
- Attach short “what changed / what is next” blurbs to each phase to reinforce the learning narrative.
- Update `tests/docs/12-test-commands.md` with the streamlined commands so the workflow remains easy to follow.

## 9. Risks & Mitigations
- **Global state in Flask apps:** Import-time singletons (`apps/api/main.py`) complicate isolation and violate stateless deployment goals. *Mitigation:* centralize app factory fixture that resets globals via helper functions; use monkeypatch to swap `BASController`/Firestore factories and assert cleanup in teardown.
- **Heavy dependency graph in `tests/conftest.py`:** Could break when splitting fixtures. *Mitigation:* incremental refactor with fallback to legacy imports; run full suite each phase to catch regressions.
- **Manual coverage drift:** Without CI guardrails, coverage reports can become stale. *Mitigation:* save hashes of local reports with each phase’s notes and re-run the baseline before publishing portfolio updates.
- **Optional dependencies (Google Cloud sink):** Hard to exercise without libs. *Mitigation:* mock modules, mark tests with `@pytest.mark.optional_dep` and skip gracefully when packages missing.
- **Parallel test execution:** Splitting fixtures may expose hidden race conditions. *Mitigation:* enforce deterministic queue draining, leverage `pytest-xdist --dist=loadscope` once suites stabilized, and add stress tests targeting roadmap reliability goals.
- **Roadmap drift:** System improvements evolve; tests may lag updated requirements. *Mitigation:* maintain alignment checklist in documentation and update coverage contexts when roadmap changes.

## 10. Open Questions & Follow-Ups
- When should GitHub Actions coverage guardrails come online once local runs stabilize at ≥90%?
- Do existing `tests/unit/auth` suites migrate into the new layered layout during the coverage push or after the milestone?
- Which contract validators merit re-enabling first (API vs Auth) when preparing CI automation?
- What lightweight stress/concurrency harness (xdist, hypothesis) best showcases horizontal scale behavior for adapters and platform helpers?
- How often should the portfolio snapshot refresh (per phase vs monthly) to reflect measurable coverage progress?

## 11. Future Enhancements
- Automate coverage guardrails (GitHub Actions matrix jobs, fail-under thresholds, artifact uploads) once local coverage stabilizes.
- Reintroduce themed coverage contexts (architecture/reliability/security) using `coverage run --context`, pairing them with lightweight dashboards or digests.
- Expand stress/concurrency scenarios (xdist, property-based fuzzers) to demonstrate horizontal scale readiness for adapters and platform code.
- Integrate contract validation toggles into CI with alerting, enabling portfolio-friendly "contract failure" metrics.
- Layer in security/static analysis tooling (Semgrep, Bandit) after the 90% milestone to round out the reliability narrative.

## 12. Next Steps (Immediate)
- Approve Phase 0 work; run the simplified `pytest --cov` baseline and capture current coverage per directory.
- Draft the fixture split outline focused on stateless factories and deterministic mocks/fakes.
- Create lightweight tracking notes for Phases 1–3 (API, Auth, Adapters/Platform) with coverage checkpoints and contract priorities.
- Update `tests/docs/12-test-commands.md` and `docs/metrics/coverage-notes.md` to reflect the streamlined workflow.
- Assemble an initial portfolio snapshot (baseline metrics + qualitative learnings) to showcase progress after Phase 1.


