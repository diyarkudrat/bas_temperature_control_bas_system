# Coverage Artifacts

Phase R1 establishes a consistent coverage baseline flow that emits both HTML and JSON
artifacts segmented by roadmap theme contexts (`architecture`, `reliability`, `security`).

## Running the Baseline Script

```shell
scripts/coverage_baseline.sh [--suite all|api|auth|logging] [-- <additional pytest args>]
```

Key behaviors:

- Executes the unit suites three times, once per roadmap theme, using `coverage run --context=<theme>`.
- Combines the generated `.coverage.*` data files, then renders reports to `coverage/html/` and `coverage/baseline.json`.
- Honors optional environment overrides:
  - `PYTEST_TARGETS`: override the test paths executed (space-delimited).
  - `PYTEST_MARKER_ARCHITECTURE`, `PYTEST_MARKER_RELIABILITY`, `PYTEST_MARKER_SECURITY`: pytest expressions appended per theme run.

## Outputs

- `coverage/html/index.html`: Human-friendly HTML report.
- `coverage/baseline.json`: Machine-readable report with coverage contexts preserved for downstream dashboards.

Both artifacts are ignored by Git; rerun the script whenever you need fresh metrics.

## Troubleshooting

- Ensure the root `.coveragerc` is present; the script relies on it for include/omit rules.
- If tests rely on optional plugins, pass `--` followed by standard pytest flags (e.g., `--maxfail=1`).
- For focused debugging, set `PYTEST_TARGETS="tests/unit/api"` to limit scope while preserving context tagging.

