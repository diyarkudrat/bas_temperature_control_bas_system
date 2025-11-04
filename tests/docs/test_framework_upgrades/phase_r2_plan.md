## Phase R2 Patch Plan — Test Orchestration Enablement

### Objectives
- Stand up dedicated `nox` sessions and developer-facing wrappers for API, Auth, and Logging unit suites to accelerate local iteration.
- Normalize how coverage-aware test runs are invoked so CI and local workflows share identical entry points.
- Capture CI runner environment decisions (OS, Python version, caching strategy, artifact retention) in a durable reference for downstream phases.

### Current Observations
- `noxfile.py` exists but lacks component-specific sessions and still reflects legacy monolith tasks.
- No dedicated `make` (or equivalent) commands bundle coverage contexts delivered in Phase R1.
- CI pipeline configuration is undecided, leaving open questions about cache mounts, parallelism, and artifact upload paths.

### Deliverables
1. Updated `noxfile.py` introducing sessions such as `tests_unit_api`, `tests_unit_auth`, and `tests_unit_logging` that:
   - Honor Phase R1 coverage orchestration (invoke `coverage run --context=<theme>` via helper script).
   - Respect opt-in plugin flags and environment configuration established in the fixture plan.
2. Developer convenience targets (`Makefile` or `justfile`) mapping to the new `nox` sessions (`make test-api-unit`, etc.).
3. Decision record outlining CI environment choices (runner, Python version, dependency caching, artifact retention) with explicit owner + revisit date.
4. Documentation updates summarizing the orchestration workflow for teammates and hiring portfolio reviewers.

### Implementation Steps
1. Audit `noxfile.py` for redundant legacy sessions; add reusable helper functions to share dependency installs and coverage invocations.
2. Define new `nox` sessions:
   - Use parametrization to limit scope (e.g., API sessions only install API extra dependencies).
   - Invoke Phase R1 `scripts/coverage_baseline.sh --suite api` (or equivalent) to ensure context-tagged coverage is captured.
3. Update `Makefile` with phony targets that call `nox -s tests_unit_api` etc., ensuring developers can run `make test-api-unit` as documented in Phase 5 notes.
4. Draft CI environment decision doc (`docs/decisions/2025-XX-ci-runner.md`) capturing:
   - Runner type (GitHub Actions Ubuntu 24.04? self-hosted?).
   - Python version alignment, dependency cache location, artifact retention policy, concurrency plan.
   - Owners, risks, and revisit cadence.
5. Refresh `tests/docs/12-test-commands.md` (or create dedicated `tests/docs/test_framework_upgrades/orchestration.md`) with:
   - Command matrix showing local vs CI invocations.
   - Expected runtime, coverage context interactions, and how to select subsets (`--tags`).
6. Validate on developer workstation and record timing metrics to include in the documentation as proof of performance improvements.

### Files to Touch
- `./noxfile.py`
- `./Makefile` (or `./Justfile` if that is the standard)
- `./scripts/coverage_baseline.sh` (augment with suite selector flag if needed)
- `./tests/docs/test_framework_upgrades/orchestration.md` (new) or update `tests/docs/12-test-commands.md`
- `./docs/decisions/2025-XX-ci-runner.md` (new decision record; final name TBD)

### Testing & Validation
- `nox -s tests_unit_api` runs to completion and drops phase-aligned coverage artifacts without side effects.
- `nox -s tests_unit_auth`/`tests_unit_logging` succeed on macOS development machine; capture runtimes for benchmarking.
- `make test-api-unit` (and analogous targets) execute expected `nox` sessions.
- Run spot-check `pytest` invocations outside `nox` to ensure compatibility remains intact.

### Risks & Mitigations
- **Dependency drift between sessions:** Centralize dependency specification via `nox.options.sessions` defaults and freeze versions in shared requirement files.
- **Developer friction adopting `nox`:** Provide quickstart in documentation, add shell completion hints, and consider fallbacks (`PYTEST_ADDOPTS` snippet).
- **CI decision paralysis:** Set a time-boxed review with stakeholders; document trade-offs in the decision record to prevent Phase R3 blocking.

### Exit Criteria Checklist
- [ ] Component-scoped `nox` sessions merged and verified locally.
- [ ] Developer wrapper commands documented and functioning (`make test-*-unit`).
- [ ] CI environment decision record written, reviewed, and linked from project plan.
- [ ] Orchestration documentation updated with runtime expectations and troubleshooting tips.

