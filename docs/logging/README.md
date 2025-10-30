# Logging Library — Phase 2 Overview

`logging_lib` now ships with the Phase 2 runtime upgrades. Highlights:

- **Structured schema** – `logging_lib.schema` emits canonical JSON documents with timestamps, service/env tags, and schema versioning.
- **Async dispatcher** – Background worker threads drain a bounded queue, batching records with retry/backoff semantics (<1 ms enqueue p95 target).
- **Dual sinks** – Stdout NDJSON sink for Cloud Run ingestion plus an optional Google Cloud Logging API sink (`LOG_SINKS=stdout,gcl`) with trace/span enrichment.
- **Configuration** – `logging_lib.config` exposes env-driven `LoggingSettings` (queue sizing, batch size, flush intervals, retry timings, sink selection).
- **Metrics** – `logging_lib.metrics` tracks drops, retries, queue depth, and flush durations for observability and alerting.
- **Diagnostics** – In-memory sink available for local testing (`LOG_SINKS=stdout,memory`), with `logging_lib.logger.dump_memory_sink()` helper.

Usage sketch:

```python
from logging_lib import configure, get_logger, logger_context

configure(service="api", env="local")
logger = get_logger("bootstrap")

with logger_context(rid="abc123"):
    logger.info("starting")
```

Operational guidance (queue sizing, retry tuning, verifying Cloud Logging ingestion) lives in `docs/logging/operations.md`. Future phases will add Flask context propagation and advanced sampling/redaction controls. See `docs/logging/design_plan.md` and `docs/logging/implementation_phase_plan.md` for roadmap details.


