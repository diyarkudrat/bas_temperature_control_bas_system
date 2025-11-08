# Coverage Notes Log

Record each local `pytest --cov` baseline run here.

| Date | API % | Auth % | Adapters % | Platform % | Runtime (mm:ss) | Highlights / Next Actions |
|------|-------|--------|------------|-------------|-----------------|---------------------------|
| 2025-11-08 | n/a | n/a | n/a | n/a |  | Baseline run blocked: Google Cloud Firestore/Protobuf dependencies fail under Python 3.14 (`TypeError: Metaclasses with custom tp_new`). Need shim or selective skip before coverage capture. |

## Logging Tips
- After each run, append a new row with the latest coverage percentages and wall-clock runtime.
- Summarize what changed (e.g., “Added auth token failure tests”) and the next focus area.
- When generating HTML reports for the portfolio, note their location for quick reference.

