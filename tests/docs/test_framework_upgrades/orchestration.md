## Test Orchestration Playbook

Phase R2 introduces standardized orchestration entry points so local developers, CI,
and portfolio reviewers run the same coverage-aware workflows.

### Quick Commands
- `make test-api-unit` → runs `nox -s tests_unit_api`, which delegates to
  `scripts/coverage_baseline.sh --suite api` for themed coverage.
- `make test-auth-unit` → executes Auth service unit coverage flow.
- `make test-logging-unit` → executes logging library coverage flow.
- `make coverage-baseline` → runs the full multi-suite coverage sweep.

All commands honor the roadmap coverage contexts (`architecture`, `reliability`,
`security`) via the baseline script. Use `make … -- POSARGS` or `nox -s … -- POSARGS`
to pass additional pytest flags (for example `--maxfail=1`).

### NOX Sessions

| Session | Targets | Notes |
|---------|---------|-------|
| `tests_unit_api` | `tests/unit/api`, `tests/unit/api/http` | Spins up coverage runs per roadmap theme; accepts extra pytest args. |
| `tests_unit_auth` | `tests/unit/auth` | Uses the same coverage contexts to validate Auth service behavior. |
| `tests_unit_logging` | `tests/unit/logging` | Focused on the logging library queues, sinks, and redaction helpers. |

Each session installs local pytest/coverage tooling inside its own virtual env and
exports the repo root on `PYTHONPATH` so imports like `auth.*` resolve consistently.

### Fixture Architecture
- `tests/conftest.py` now limits itself to path setup, lightweight marker registration,
  and optional opt-in to legacy contract fixtures via `BAS_ENABLE_CONTRACT_FIXTURES`.
- Layered domain fixtures live under `tests/unit/**/conftest.py`, each consuming helpers
  from `tests/utils/` (`flask_app_factory`, `env`, `logging`, `healthcheck`).
- Common autouse fixtures in `tests/unit/conftest.py` enforce deterministic seeds,
  stateless clocks, and plugin isolation by default (`BAS_DISABLE_PLUGINS=1`).
- Firestore helpers moved to `tests/fixtures/firestore_fixtures.py`; they skip cleanly
  when optional dependencies are unavailable.

### Environment Variables
- `COVERAGE_CMD` — override to pin a specific coverage binary (defaults to NOX’s venv).
- `PYTEST_TARGETS` — configure via `nox` helpers; override manually for bespoke runs.
- `PYTEST_MARKER_ARCHITECTURE|RELIABILITY|SECURITY` — optional pytest expressions to
  further slice contexts without changing the script.
- `BAS_DISABLE_PLUGINS` — defaults to `1` for unit suites; set to `0` to re-enable
  heavy contract plugins or legacy behaviors.
- `BAS_ENABLE_CONTRACT_FIXTURES` — defaults to `1`; set to `0` for faster runs when
  contract validation fixtures are unnecessary.

### Runtime Expectations
- API suite: ~3 themed runs, target < 4 minutes on Apple M-series laptops.
- Auth suite: ~3 themed runs, target < 3 minutes.
- Logging suite: ~3 themed runs, target < 2 minutes.

Record actual timings after the first successful run and append them to this document
so portfolio reviewers can see the performance deltas versus the legacy setup.


