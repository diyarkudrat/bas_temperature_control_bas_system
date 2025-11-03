# Phase 2 Patch Plan — Async Runtime & Google Cloud Logging Integration

## Summary
Augment the Phase 1 library with an asynchronous dispatcher, Cloud Run–friendly stdout serialization, and a first-class Google Cloud Logging (GCL) API adapter. This phase ensures dual-path delivery (stdout + GCL API), resilient backpressure handling, and observability hooks for drops/retries.

## File/Module Operations
| File/Module | Operation | Notes |
| --- | --- | --- |
| `logging_lib/config.py` | Update | Add async + GCL settings (batch size, flush interval, worker count, retry/backoff, enable flags). |
| `logging_lib/queue.py` | Update | Replace simple queue with lock-free ring buffer or `queue.SimpleQueue` + drop accounting; expose non-blocking put semantics. |
| `logging_lib/dispatcher.py` | Update | Introduce background worker thread(s), batch flushing, retry/backoff, metrics counters. |
| `logging_lib/logger.py` | Update | Ensure enqueue path stays non-blocking (<1 ms p95) and delegates flush triggering to dispatcher. |
| `logging_lib/sinks/stdout.py` | Update | Ensure RFC3339 timestamp formatting, include Cloud Logging severity metadata, optionally attach resource labels. |
| `logging_lib/sinks/gcl_api.py` | Add | New adapter using `google-cloud-logging` client with batching, retry policy, and resource labeling. |
| `logging_lib/metrics.py` | Add | Lightweight counters for drops, retries, last flush duration; expose for integration with Prometheus later. |
| `logging_lib/__init__.py` | Update | Export new configuration settings, sink registration API, and metrics accessors. |
| `docs/logging/README.md` | Update | Document async runtime behavior, configuration knobs, and GCL integration instructions. |
| `docs/logging/operations.md` | Add | Operational runbook covering queue sizing, retry tuning, failure modes, and metrics interpretation. |

## Implementation Steps
1. **Configuration Enhancements**
   - Extend `LoggingSettings` with `batch_size`, `flush_interval_ms`, `worker_threads`, `gcl_enabled`, `gcl_project`, `gcl_log_name`, `retry_initial_backoff_ms`, `retry_max_backoff_ms`, `flush_timeout_ms`.
   - Support env vars (`LOG_BATCH_SIZE`, `LOG_FLUSH_MS`, `LOG_ASYNC_WORKERS`, `LOG_GCL_ENABLED`, `LOG_GCL_PROJECT`, `LOG_GCL_LOG_NAME`, `LOG_RETRY_INITIAL_MS`, `LOG_RETRY_MAX_MS`).

2. **Async Dispatcher**
   - Implement worker thread pool started during `configure()`, each consuming from queue and flushing batches using new `flush_batch(records)` method.
   - Implement backpressure strategy: non-blocking `put` with queue capacity; on overflow, drop lowest severity and increment drop counter, emit diagnostic warning via internal sink.
   - Add exponential backoff on sink errors; limit retries per batch; mark failures with metrics and fallback logging.

3. **Queue Improvements**
   - Switch to ring buffer with atomic indices (`queue.SimpleQueue` or custom structure) to minimize lock contention.
   - Record statistics: current depth, total dropped, last dropped level.

4. **Sinks**
   - Stdout sink: include `severity` field derived from level, ensure newline-delimited JSON, add optional `logging.googleapis.com/trace` for trace correlation when trace IDs present.
   - GCL API sink: instantiate `google.cloud.logging.Client`, configure `Batch` objects, add labels (`service`, `env`, `component`), handle service account credentials via ADC; expose graceful shutdown for worker threads.

5. **Metrics & Instrumentation**
   - Provide counters (`metrics.dropped_total`, `metrics.retries_total`, `metrics.flush_duration_ms`, `metrics.queue_depth`), accessible via `logging_lib.metrics.get_metrics()`.
   - Emit internal WARN log when drop rate exceeds threshold (configurable via `LOG_DROP_ALERT_RATE`).

6. **Testing & Validation (non-code)**
   - Document manual benchmarking steps (e.g., script generating synthetic logs, measure enqueue latency, confirm dual sink output).
   - Provide instructions for verifying Cloud Logging ingestion (stdout + API) via `gcloud logging read` commands.

## Acceptance Criteria
- `configure()` starts background workers; `get_logger().info()` enqueues logs without blocking main thread beyond p95 <1 ms under nominal load.
- Logs are emitted to stdout and, when `LOG_GCL_ENABLED=1`, to GCL API with correct labels and severity; failures are retried with backoff and surfaced via metrics.
- Drop count, retry count, and queue depth metrics are tracked and accessible programmatically.
- Documentation reflects new runtime behavior, configuration, and operations guidance.

