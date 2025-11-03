# Logging Library v2 — Implementation Phases

## Phase 1 — Core Library Bootstrap
- Establish package structure `logging_lib/` with modules for facade, schema, config, redaction, sampling, async dispatcher, and sink interfaces.
- Implement canonical JSON schema builder with validation utilities and reserved key enforcement.
- Create configuration loader honoring env/file/default precedence and expose `get_settings()`.
- Build facade API `get_logger`, `logger_context`, and logging methods (debug/info/warn/error/critical) that feed an in-memory queue.
- Provide placeholder sinks (stdout JSON writer, in-memory collector) wired through dispatcher; instrumentation counters for drops/errors.
- Document module layout and public API signatures in `README` or docstring.

## Phase 2 — Google Cloud Logging Integration & Async Runtime
- Implement lock-free ring buffer queue with background worker thread(s) driven by flush interval and batch size settings.
- Build Cloud Logging stdout serializer aligned with schema; map levels to `severity` and ensure RFC3339 timestamps.
- Add Google Cloud Logging API adapter using official client with resource labels, retries, and exponential backoff.
- Ensure dispatcher supports dual-sink fan-out (stdout + GCL API) with failure isolation and drop accounting.
- Wire configuration flags (`LOG_GCL_ENABLED`, batch sizes, timeouts) and surface health metrics via counters (e.g., drops, retries, failures).
- Add benchmarking scripts or notes to confirm p95 enqueue latency <1 ms under nominal load.

## Phase 3 — Flask Integration & Context Propagation
- Deliver Flask extension (`register_flask_context`) handling request lifecycle: generate/propagate `X-Request-Id`, parse `traceparent`, record latency.
- Provide middleware hooks for request/response logging event using new facade, injecting route/method/status/latency/tenant/user context.
- Implement context helpers for background tasks (e.g., telemetry jobs) to attach trace/span IDs.
- Add utilities for extracting Auth0 user/tenant information safely; ensure redaction policies are applied before emission.
- Update documentation with integration instructions for API, auth, and telemetry services.

## Phase 4 — Redaction, Sampling, and Policy Controls
- Finalize denylist/allowlist configuration, default redactors (hash/truncate), and custom redactor registration API.
- Implement level-aware sampling controls with respect to configuration (`LOG_SAMPLE_RATE_INFO`, etc.) ensuring ERROR/CRITICAL never sampled.
- Add structured error reporting for redaction/sampling decisions (e.g., `log_drop` warning events).
- Validate schema size limits (e.g., 16 KB) and enforce truncation policies with explicit metadata fields (e.g., `context_truncated` flag).
- Extend configuration matrix documentation describing operational tuning and security considerations.