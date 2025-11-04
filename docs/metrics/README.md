# Coverage Metrics Overview

Phase R5 adds automated governance around unit-test coverage. The CI matrix
(`.github/workflows/tests.yml`) produces component-specific coverage artifacts
(`coverage/json/*.json`, `coverage/xml/*.xml`, themed HTML reports) and uploads
them for each pull request.

Key scripts:

- `scripts/coverage/update_exceptions.py` — synchronises the coverage exception
  register with the latest JSON report.
- `scripts/coverage/regression_guard.py` — fails the build when coverage drops
  by more than the configured threshold relative to the baseline in
  `coverage/baselines/`.
- `scripts/coverage/generate_digest.py` — composes a markdown digest summarising
  recent coverage results; executed weekly via
  `.github/workflows/coverage-digest.yml` and uploaded as `coverage-weekly`.

Artifacts:

- `coverage/html/<suite>/index.html` — per-suite themed HTML report.
- `coverage/json/<suite>.json` — machine-readable coverage metrics used by
  automation scripts.
- `tests/docs/test_framework_upgrades/coverage_exceptions.md` — updated in CI to
  reflect modules below the fail-under threshold.

Operational Notes:

- Update the baselines under `coverage/baselines/` whenever a new acceptable
  coverage level is established on `main`; this keeps regression guard relevant.
- The digest workflow runs every Monday at 12:00 UTC and can also be triggered
  manually via the **Coverage Digest** workflow dispatch.
- Additional dashboards (Codecov, Grafana, etc.) can ingest the JSON artifacts
  if desired; ensure tokens or webhooks are added to repository secrets before
  extending the workflows.


