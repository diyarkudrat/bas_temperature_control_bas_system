# Logging Library Operations Guide

## Key Metrics
- `dropped_total`, `dropped_levels`: Monitor for backpressure issues. Alert when drop rate exceeds `LOG_DROP_ALERT_RATE`.
- `retries_total`: Indicates Cloud Logging API retries. Sustained increments imply downstream throttling or auth issues.
- `flush_total`, `last_flush_duration_ms`: Track throughput and worker efficiency.
- `queue_depth`: Helps size `LOG_QUEUE_SIZE` and `LOG_BATCH_SIZE`.

Retrieve metrics programmatically:

```python
from logging_lib import get_metrics

snapshot = get_metrics().as_dict()
```

## Configuration Knobs
- `LOG_QUEUE_SIZE`: Increase for bursty workloads; ensure memory headroom.
- `LOG_BATCH_SIZE`: Larger batches improve throughput but add latency; start with 128.
- `LOG_FLUSH_MS`: Reduce for latency-sensitive services (minimum ~50 ms).
- `LOG_ASYNC_WORKERS`: Scale with CPU/GCL throughput. 2–4 threads suit most Cloud Run services.
- `LOG_RETRY_INITIAL_MS` / `LOG_RETRY_MAX_MS`: Tune for Cloud Logging quota behaviour. Default exponential backoff (100 ms → 2000 ms).
- `LOG_GCL_ENABLED`: Keep `1` in production to ensure API delivery alongside stdout.

## Verifying Delivery
1. **Stdout path**: `gcloud logging read 'resource.type="cloud_run_revision" AND jsonPayload.service="api"' --limit=10`
2. **GCL API path**: Filter by log name `projects/<project>/logs/<LOG_GCL_LOG_NAME>` to confirm structured payload + severity.
3. **Trace linkage**: Ensure entries contain `logging.googleapis.com/trace` with the correct project/trace ID.

## Failure Modes & Response
- **Queue drops increasing**: Raise `LOG_QUEUE_SIZE`, scale `LOG_BATCH_SIZE`, or add worker threads. Investigate service throughput (logs per request) and reduce INFO volume via sampling (Phase 4).
- **Retries spiking**: Check Cloud Logging quotas; verify service account roles (`roles/logging.logWriter`, `roles/logging.configWriter`).
- **Credential errors**: Cloud Run service must run as the logging-enabled service account; for local runs export `GOOGLE_APPLICATION_CREDENTIALS`.
- **High flush durations**: Review batch size or sink latency. For local dev, disable API sink via `LOG_GCL_ENABLED=0`.

## Graceful Shutdown
`configure()` manages worker lifecycle. On container stop, call `logging_lib.configure()` once during startup and let the runtime terminate threads. For manual teardown (tests), call `logging_lib.logger.reset_loggers()`.


