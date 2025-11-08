# Coverage Phase Tracking Notes

| Phase | Target Area | Key Workstreams | Coverage Goal | Status | Notes |
|-------|-------------|-----------------|---------------|--------|-------|
| 0 | Framework Simplification | Scoped `.coveragerc`, trimmed `pytest.ini`, baseline `pytest --cov`, fixture outline | Establish baseline | 🟡 In Progress | Verify coverage per directory and log results in `docs/metrics/coverage-notes.md`. |
| 1 | API Service (`apps/api`) | Expand HTTP/middleware/client tests, finalize API fixtures, ensure stateless factories | ≥90% | ⬜ Planned | Focus on auth provider branches, middleware fallbacks, and error handling. |
| 2 | Auth Service (`apps/auth_service`) | Token settings, replay protection, bootstrap failures, request hooks | ≥90% | ⬜ Planned | Prioritize configuration failure modes and contract coverage for token policies. |
| 3 | Adapters & Platform (`adapters/`, `app_platform/`) | Protocol contracts, retry behavior, shared bootstrap utilities | ≥90% | ⬜ Planned | Capture deterministic retries and platform headers/tracing behavior. |

## Capture Template (per phase)
- Date range:
- Coverage snapshot (API / Auth / Adapters / Platform):
- Runtime (pytest wall-clock):
- Highlights:
  - Wins:
  - Challenges:
- Next actions:

