# Phase R5 — CI & Governance Hardening Patch Plan

## Intent & Success Metrics
- **Objective:** Codify test governance by enforcing ≥90% coverage gates per component, publishing reliable artifacts (XML/JSON/HTML), and automating coverage regression alerts.
- **Success Metrics:**
  - GitHub Actions (or chosen CI runner) matrix enforcing fail-under thresholds (`unit-api`, `unit-auth`, `unit-logging`).
  - Coverage artifacts uploaded per job and merged into `coverage/` history.
  - Automated notification when coverage drops >2% or fails baseline.
  - Coverage exception register updated on each pipeline run.
- **Exit Criteria:** Coverage jobs green with hard fail-under, artifacts persisted, governance docs refreshed, and metrics digest automation live for two consecutive cycles.

## Dependencies & Preparation
- Phase R4 suites merged and green locally (`tests/unit/api`, `tests/unit/auth_service`, `tests/unit/logging`).
- `.coveragerc`, `pytest.ini`, and `nox` sessions validated with coverage contexts.
- CI credentials available for artifact upload (e.g., GitHub Actions cache/storage, Codecov token if applicable).
- `coverage_exceptions.md` baseline established with owners/next reviews.
- `scripts/coverage_baseline.sh` supports `--suite api|auth|logging` (update if gaps).

## Workstream A — CI Matrix Implementation (2 days)
**Goal:** Create reliable CI matrix jobs with deterministic environments and per-component gating.

### A1. Workflow Definition
- Target files: `.github/workflows/tests.yml` (or equivalent), `scripts/ci/` helpers.
- Tasks:
  - Add matrix strategy with entries `unit-api`, `unit-auth`, `unit-logging` using Python 3.11.
  - Install dependencies via project `requirements-dev.txt` and `nox` with caching (e.g., `actions/cache`).
  - Invoke `nox -s tests(unit_api|unit_auth|unit_logging)`; pass through `-- --cov-report=xml:coverage/<suite>.xml --cov-report=json:coverage/<suite>.json`.
  - Ensure workflow exports coverage context env (`COVERAGE_CONTEXT=api|auth|logging`).
- Patch plan:
  - Create/update workflow file with matrix, caching steps, artifact upload.
  - Document command invocation in job-level comments for maintainers.

### A2. Fail-Under Enforcement
- Tasks:
  - Update `nox` sessions and/or `coverage_baseline.sh` to accept `--fail-under` per suite (default 90, allow override via env for soft start).
  - Ensure CI passes `COVERAGE_FAIL_UNDER=90` (auth security-critical modules may target 92 via env override).
- Patch plan:
  - Modify `scripts/coverage_baseline.sh` to wire `coverage json` output and `coverage report --fail-under` using context-specific thresholds.
  - Add fail-under config to `pytest.ini` or `nox` environment to avoid drift.

### A3. Artifact Publication
- Tasks:
  - Upload XML, JSON, HTML coverage artifacts per job (compressed) for audit trail.
  - Add summary comment (if using GitHub Actions) using `actions/upload-artifact` and optional `github-script` for PR coverage diff.
- Patch plan:
  - Extend workflow with `upload-artifact` steps naming artifacts `coverage-unit-api`, etc.
  - Add script (Python or bash) under `scripts/ci/coverage_summary.py` to parse JSON and emit summary table (include architecture/reliability/security tags).

## Workstream B — Governance Automation (1 day)
**Goal:** Automate coverage exception register updates, regression detection, and reporting.

### B1. Coverage Exception Sync
- Tasks:
  - Extend `scripts/coverage_baseline.sh` (or new script) to compare current coverage JSON vs thresholds; update `tests/docs/test_framework_upgrades/coverage_exceptions.md` (append row or mark resolved).
  - Provide dry-run mode for local usage.
- Patch plan:
  - Add Python helper `scripts/coverage/update_exceptions.py` reading coverage JSON, mutating markdown via templated section.
  - Integrate script into CI job post-test step (commit skipped; artifact plus PR suggestion comment).

### B2. Regression Alerts
- Tasks:
  - Detect >2% coverage drops across successive runs; fail job or emit Slack/email webhook.
  - Use `coverage/<suite>.json` artifact + cached baseline (store previous JSON in artifact store or repository branch `coverage-history/`).
- Patch plan:
  - Implement `scripts/coverage/regression_guard.py` comparing current JSON to previous (download via `actions/download-artifact` or repo path).
  - Configure CI step to run guard; on failure, set status + annotate summary.

### B3. Metrics Digest Automation
- Tasks:
  - Generate weekly coverage delta report (markdown or JSON) summarizing runtime, failures, exceptions.
  - If using GitHub Actions, schedule `cron` job to run digest script and push to `docs/metrics/coverage-weekly.md` or open PR.
- Patch plan:
  - Add scheduled workflow `coverage-digest.yml` invoking `scripts/coverage/generate_digest.py` which consumes stored JSON history.
  - Document output location and distribution (Slack/email) in README.

## Workstream C — Documentation & Observability (1 day)
**Goal:** Update docs and dashboards to reflect new governance model.

### C1. Documentation Refresh
- Tasks:
  - Update `tests/docs/12-test-commands.md` with CI commands, fail-under behavior, artifact locations.
  - Add governance section to `tests/docs/test_framework_upgrades/orchestration.md` covering matrix jobs and monitoring.
- Patch plan:
  - Document how to run `scripts/coverage/update_exceptions.py --dry-run` locally.
  - Link to coverage artifacts and dashboards (Codecov/Sonar) if configured.

### C2. Dashboard Integration
- Tasks:
  - If Codecov or Sonar is used, configure upload from CI (`codecov-action` or sonar scanner) with per-component flags.
  - Update `docs/metrics/README.md` (create if missing) explaining dashboards and how to interpret architecture/reliability/security contexts.
- Patch plan:
  - Add Codecov step with flags `api`, `auth`, `logging`; ensure secrets stored in CI.
  - Document fallback approach if third-party service unavailable (e.g., rely on JSON + Grafana board).

### C3. Portfolio & Stakeholder Artifacts
- Tasks:
  - Update portfolio packet with CI screenshots and alert workflow description.
  - Append R5 milestone summary to `tests/docs/test_framework_upgrades/phase_r5_plan.md` once complete.
- Patch plan:
  - Prepare template `docs/portfolio/coverage_memo_R5.md` summarizing governance improvements.
  - Capture sample CI run outputs (copy sanitized logs into docs or link to permalink).

## Risk Management
- **Flaky Coverage Failures:** Mitigate by caching dependencies, pinning coverage tool versions, and running `coverage combine` only on clean env.
- **Artifact Growth:** Compress HTML reports and prune old artifacts (retain last 10 runs) via workflow retention settings.
- **Markdown Automation Conflicts:** Use JSON snapshot + deterministic templating to avoid large merges; run automation in CI with `pull_request` comment rather than direct commits.
- **Secret Management:** Ensure tokens for Codecov/Slack stored as GitHub secrets; document rotation cadence.

## Validation Checklist
- [ ] Matrix CI workflow merged with coverage gating and artifact uploads.
- [ ] `scripts/coverage_baseline.sh` (or successor) enforces fail-under thresholds per suite.
- [ ] Coverage exception register auto-updates (manual review for accuracy).
- [ ] Regression guard prevents >2% coverage drops without alert.
- [ ] Weekly digest scheduled and produces sample report stored under `docs/metrics/`.
- [ ] Documentation (`12-test-commands.md`, orchestration guide) reflects new workflows.


