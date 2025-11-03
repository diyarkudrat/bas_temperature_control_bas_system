# Logging Library Integration Guidelines — Phase 4

## Configuration Surfaces
- `LOG_REDACTION_DENYLIST`, `LOG_REDACTION_CONTEXT_DENYLIST`: comma lists of sensitive keys hashed with deterministic salt.
- `LOG_REDACTION_TRUNCATE_LENGTH`, `LOG_REDACTION_TRUNCATE_SUFFIX`: ensures redacted payloads stay below 16 KB hard cap.
- `LOG_SAMPLING_ENABLED`, `LOG_SAMPLE_RATE_<LEVEL>`: probabilistic sampling with deterministic stickiness on `LOG_SAMPLING_STICKY_FIELDS`.
- `LOG_PAYLOAD_LIMIT_BYTES`: guards sink payload size; defaults to `16384` bytes for stdout + GCL.
- `LOG_SAMPLING_ALWAYS_EMIT`: space/comma list of levels that bypass sampling (default `ERROR,CRITICAL`).

## Deployment Playbook
- Apply new env vars via service manifests; redaction and sampling settings are immutable at runtime.
- Verify configuration in staging with `GET /api/health` and `logging_lib.metrics.get_metrics()`.
- Roll out sampling in two stages: start with high default rate (`1.0`), then dial down `INFO`/`DEBUG` after metrics confirm no drops.
- Use the drop notice `log_drop` warnings to configure queue sizing and sink retry thresholds.
- Export `payload_truncated`, `context_truncated` counters to dashboards; treat sustained growth as an SLO breach.

## Operational Tips
- Prefer deterministic stickiness keys (`request_id`, `trace_id`) so distributed workers make consistent sampling decisions.
- When onboarding a new service, start with `LOG_REDACTION_ALLOWLIST=*` and gradually tighten deny lists as payloads stabilise.
- Custom redactors can be registered via `LOG_REDACTION_MODULE=<module>`, implementing `register_redactors(registry) -> None`.
- For device telemetry, set `LOG_SAMPLE_RATE_WARNING=1.0` to retain noisy hardware alerts while trimming `INFO` chatter.
- Capture integration tests around `logging_lib.queue.emit_drop_event` to keep regression coverage on bounded queues.

