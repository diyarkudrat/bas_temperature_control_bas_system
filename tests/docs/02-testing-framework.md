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

## Execution & Orchestration

- **Virtual environment:** `python3 -m venv .venv && source .venv/bin/activate` keeps local runs aligned with CI. Install dependencies with `pip install -r apps/api/requirements.txt`.
- **Pytest direct:** `python -m pytest tests/unit -v --maxfail=1` for fast feedback. Add markers (e.g., `-m auth`) or `-k` expressions for focused runs.
- **NOX sessions:** `nox -s tests_unit_api|tests_unit_auth|tests_unit_logging` mirror CI’s isolated environments and automatically propagate coverage configuration.
- **Coverage baseline script:** `scripts/coverage_baseline.sh --suite all` runs architecture, reliability, and security contexts per suite, producing HTML/XML/JSON artifacts and refreshing coverage baselines.
- **Utility commands:** See `12-test-commands.md` for expanded cheat sheets, including regression guard and coverage exception helpers.

## Component Playbooks

### API Service (`apps/api`)

- **Fixtures & helpers:** `create_api_app`, `api_client`, and `api_request_context` (in `tests/unit/api/conftest.py`) enforce stateless factories and inject deterministic auth/tenant doubles. Utility stubs (`firestore_stub.py`, `rate_limiter_stub.py`) model downstream dependencies.
- **Key suites:** 
  - `tests/unit/api/test_bootstrap.py` validates auth provider selection, Firestore health handling, and metrics wiring.
  - `tests/unit/api/http/test_health_routes.py` and `test_rate_limit_middleware.py` exercise readiness, liveness, and rate-limit behaviors across contexts.
  - `tests/unit/api/clients/test_auth_service_client.py` and `test_device_credentials_service.py` validate outbound integrations, rotation windows, and redaction safeguards.
- **Coverage target:** ≥90% line coverage enforced through `nox -s "tests(unit_api)"` and top-level baseline runs. Record carve-outs via `scripts/coverage/update_exceptions.py --suite api`.

### Logging Library (`logging_lib`)

- **Core fixtures:** `_DeterministicDispatcher`, `logging_settings`, `memory_sink`, and `memory_logger` (in `tests/unit/logging/conftest.py`) ensure synchronous, deterministic dispatcher behavior and clean sink state per test.
- **Key suites:** 
  - `tests/unit/logging/test_config.py` confirms manager reconfiguration and stdout fallbacks.
  - `test_dispatcher_queue.py` verifies batching, retry metrics, and drop notifications (`RingBufferQueue.emit_drop_event`).
  - `test_context_management.py` and `test_sampling_redaction.py` enforce context isolation, sampling determinism, and redaction policy.
  - Optional sink coverage (`pytest.importorskip("google.cloud.logging")`) gates cloud-specific assertions.
- **Coverage target:** CI job `unit-logging` enforces ≥90% via `nox -s "tests(unit_logging)"`. Use JSON outputs (`coverage/json/logging.json`) when auditing exceptions.

### Health & Observability

- **Readiness & liveness:** `tests/unit/api/http/test_health_routes.py` asserts `/api/health` metadata and readiness gatekeeping before/after `init_auth`. Use `create_api_app()` without initialization to simulate cold starts.
- **Rate limiting:** `test_rate_limit_middleware.py` exercises allow/deny/shadow flows. The `RateLimiterStub` and `_enter_rate_limited_request` helpers provide deterministic coverage of per-request throttling; `caplog` is leveraged for observability assertions.
- **Logging & metrics:** `tests/unit/api/test_bootstrap.py` validates `AuthMetrics` wiring, while `tests/unit/logging/test_dispatcher_queue.py` confirms structured drop notices and telemetry. Always clear context vars via `clear_context()` in fixtures to prevent tenant/request leakage.
- **Run locally:** `make test-api-unit -- --maxfail=1` and `make test-logging-unit -- --maxfail=1` offer quick confidence checks that align with the orchestration plan.

## Coverage Governance

- **Register:** `tests/docs/test_framework_upgrades/coverage_exceptions.md` tracks any module below the 90% guardrail. Each row must include owner, rationale, mitigation plan, and next review date; historical entries are never deleted.
- **Current status (Phase R6):**

| Module / Path | Current Coverage | Exception Type | Owner | Rationale | Mitigation Plan | Next Review |
|---------------|------------------|----------------|-------|-----------|-----------------|-------------|
| _None_ | n/a | n/a | n/a | All suites meet or exceed fail-under (90–92%). | Continue monitoring via CI artifacts and weekly digest. | 2026-01 |

- **Audit workflow:** After each baseline run, execute `python scripts/coverage/update_exceptions.py --suite all --dry-run` and reconcile results with the register. Governance outcomes feed the weekly coverage digest and roadmap reviews.

## Metrics & Reporting

Establish and monitor coverage/runtime baselines with the following loop:

1. Refresh environment: ensure `.venv` is active and dependencies installed.
2. Generate themed coverage artifacts:

   ```bash
   time scripts/coverage_baseline.sh --suite all
   ```

   - Produces `coverage/json/combined.json`, `coverage/html/combined/index.html`, and `coverage/xml/combined.xml`.
   - Contexts (`architecture`, `reliability`, `security`) are captured automatically.
3. Record metrics:
   - Wall-clock runtime, pass/fail counts, flaky reruns (via `pytest --lf` if needed).
   - Coverage deltas compared to committed baselines (`coverage/baselines/*.json`).
4. Update the portfolio tracker and highlight notable movements in the weekly coverage digest or phase recaps.

## Roadmap Alignment

Keep testing outcomes tied to roadmap goals using the shared checklist:

| Roadmap Requirement | Phase | Implementation Evidence | Status | Owner | Next Review |
|---------------------|-------|--------------------------|--------|-------|-------------|
| Stateless API app factories | R1–R4 | `tests/unit/api/test_bootstrap.py`, `tests/unit/api/conftest.py` | ✅ Complete | Diyarkudrat | 2026-01 |
| Auth service coverage ≥90% | R4 | `tests/unit/auth_service/*`, CI `unit-auth` job | ✅ Complete | Diyarkudrat | 2026-01 |
| Logging dispatcher resilience | R4 | `tests/unit/logging/test_dispatcher_queue.py` | ✅ Complete | Diyarkudrat | 2026-01 |
| Coverage governance automation | R5 | `.github/workflows/tests.yml`, `scripts/coverage/*` | ✅ Complete | Diyarkudrat | 2025-12 |
| Coverage digest cadence | R5–R6 | `.github/workflows/coverage-digest.yml`, `docs/metrics/coverage-weekly.md` | ✅ Complete | Diyarkudrat | Monthly |
| Health/observability documentation | R6 | `tests/docs/test_framework_upgrades/health_observability.md` | ✅ Complete | Docs Guild | Quarterly |
| Portfolio packet refresh | R6 | `docs/portfolio/coverage_memo_R6.md`, slides outline | ✅ Complete | Diyarkudrat | Quarterly |
| Coverage exception ADR | R6 | `docs/decisions/2025-12-coverage-exceptions.md` | ✅ Complete | Architecture Council | 2026-02 |
| Chaos testing hooks | R7 (planned) | Pending contract migration/fixtures | ⏳ Backlog | TBD | 2026-03 |

Review the checklist after each phase milestone; mark progress (`✅`, `⏳`) and refresh review cadences to maintain governance visibility.