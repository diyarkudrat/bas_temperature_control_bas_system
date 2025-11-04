# Metrics Baseline Instructions

Use this checklist to capture Phase 1 baseline metrics before refactoring fixtures.

1. Ensure a clean virtual environment and reinstall dependencies if needed.
2. Run the default unit suite and capture runtime:
   ```bash
   time python3 -m pytest tests/unit -q \
     --cov=apps/api --cov=apps/auth_service --cov=logging_lib \
     --cov-config=coverage/.coveragerc --cov-report=term
   ```
3. Save the generated `coverage.xml` (if requested) and `term` output under `coverage/baseline/`.
4. Record flaky tests by parsing the pytest summary or rerun with `--lf` to confirm.
5. Snapshot results (runtime, coverage %, flaky count) into the portfolio metrics dashboard.


