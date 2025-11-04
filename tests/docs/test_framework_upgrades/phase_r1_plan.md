## Phase R1 Patch Plan — Coverage Infrastructure

### Objectives
- Deliver repository-wide coverage configuration scoped to `apps/api`, `apps/auth_service`, and `logging_lib`.
- Replace fragmented pytest coverage options with a single authoritative configuration.
- Produce repeatable coverage runs that emit HTML and JSON artifacts tagged by roadmap themes (`architecture`, `reliability`, `security`) so downstream reporting can slice by context.

### Current Observations
- `pytest.ini` contains duplicated `addopts` and points coverage to defunct `server/` paths.
- No `.coveragerc`; omit/include logic is embedded in ad-hoc `pytest` invocations.
- Coverage artifacts (`htmlcov/`) reflect historical runs without context tagging.

### Deliverables
1. `.coveragerc` placed under repository root with:
   - `[run]` `source = apps/api, apps/auth_service, logging_lib` and `branch = True`.
   - `omit` entries for CLI entrypoints, generated templates, and optional sinks.
   - `[report]` fail-under placeholders (documented but not enforced yet) and include patterns.
   - `[paths]` stanza if needed for CI path normalization.
2. Updated `pytest.ini` with single `addopts` referencing `--cov-config=.coveragerc` and removing legacy paths.
3. Script or `nox` target that orchestrates `coverage run --context=<theme>` executions for `architecture`, `reliability`, and `security`, combines results, and publishes HTML + JSON artifacts into `coverage/`.
4. Seed `tests/docs/test_framework_upgrades/coverage_exceptions.md` with identified carve-outs discovered during baseline run (template table acceptable).
5. Harden `.gitignore` to exclude generated coverage artifacts (`coverage/html/`, `coverage/*.json`, `htmlcov/`).

### Implementation Steps
1. Author `.coveragerc` (new file) and validate locally with `coverage debug config`.
2. Refactor `pytest.ini`:
   - Merge `addopts` blocks.
   - Ensure `-p no:legacy_plugins` (if applicable) survives refactor.
   - Reference `--cov` targets only via config.
3. Create orchestration script `scripts/coverage_baseline.sh` (or `nox` session) that:
   - Runs `coverage erase` before each cycle.
   - Executes `coverage run --context=architecture -m pytest tests/unit -m "architecture"` (or scoped directories) and repeats for `reliability` and `security` contexts.
   - Invokes `coverage combine` to consolidate data, then `coverage html -d coverage/html` and `coverage json -o coverage/baseline.json`.
   - Annotates generated `coverage/README.md` with instructions on interpreting context-tagged outputs.
4. Run the script locally; capture summary metrics and log theme-specific highlights in `coverage_exceptions.md`.
5. Update docs (`tests/docs/12-test-commands.md` or new README section) with explicit commands, context flag explanations, and expectations for runtime.
6. Commit artifacts directory structure (placeholders via `.gitkeep`) while ensuring `.gitignore` prevents generated reports from entering version control.

### Files to Touch
- `./.coveragerc` (new)
- `./pytest.ini`
- `./scripts/coverage_baseline.sh` (new; executable flag required)
- `./coverage/README.md` (new)
- `./tests/docs/test_framework_upgrades/coverage_exceptions.md` (new)
- `./.gitignore`

### Testing & Validation
- `scripts/coverage_baseline.sh` (or corresponding `nox` session) completes three themed runs and finishes with `coverage combine` without errors.
- Manual sanity checks: `coverage html` and `coverage json` outputs exist under `coverage/` with distinct context metadata.
- Confirm `pytest` without coverage still works (sanity run: `pytest -q tests/unit/api`).

### Risks & Mitigations
- **Legacy scripts expecting old `addopts`:** Communicate change and retain compatibility notes; offer transitional `PYTEST_ADDOPTS` snippet.
- **Path normalization issues in CI:** Include `[paths]` section up front; dry-run on macOS/Linux locally if possible.
- **Generated artifacts accidentally committed:** Add/update `.gitignore` entries under `coverage/` and verify via `git status` before commit.

### Exit Criteria Checklist
- [ ] `.coveragerc` merged and validated via `coverage debug config`.
- [ ] `pytest.ini` streamlined and passing unit smoke tests.
- [ ] Baseline coverage script documented and produces HTML + JSON outputs locally with context metadata.
- [ ] `tests/docs/test_framework_upgrades/coverage_exceptions.md` exists with initial entries (even if templated).
- [ ] `.gitignore` updated to exclude generated coverage artifacts (`coverage/html/`, `coverage/*.json`, `htmlcov/`).

