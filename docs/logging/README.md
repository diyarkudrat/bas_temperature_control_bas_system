# Logging Library — Phase 1 Overview

Phase 1 introduces the foundational `logging_lib` package. Highlights:

- **Structured schema** – `logging_lib.schema` emits canonical JSON documents with timestamps, service/env tags, and schema versioning.
- **Configurable settings** – `logging_lib.config` loads immutable `LoggingSettings` from environment variables and exposes `configure()` helpers.
- **Logger facade** – `logging_lib.get_logger(component)` returns a structured logger that honors severity thresholds, context managers, and redaction hooks.
- **Sinks** – Stdout NDJSON sink ships for Cloud Run ingestion. An in-memory sink can be enabled for diagnostics (`LOG_SINKS=stdout,memory`).
- **Queue & dispatcher** – A bounded queue drops oldest entries under pressure. Dispatcher flushes synchronously in Phase 1; later phases will introduce async workers and Cloud Logging adapters.

Usage sketch:

```python
from logging_lib import configure, get_logger, logger_context

configure(service="api", env="local")
logger = get_logger("bootstrap")

with logger_context(rid="abc123"):
    logger.info("starting")
```

Future phases will extend this foundation with asynchronous delivery, dual Cloud Logging sinks, Flask middleware, and advanced sampling/redaction controls. For details, see `docs/logging/design_plan.md` and `docs/logging/implementation_phase_plan.md`.


