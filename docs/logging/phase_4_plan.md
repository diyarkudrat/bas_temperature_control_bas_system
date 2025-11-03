# Phase 4 — Redaction, Sampling, and Policy Controls Patch Plan

**Summary (≤100 words):** Phase 4 hardens observability for multi-service deployments by enforcing deterministic redaction, policy-driven sampling, and schema safety rails. We will extend configuration surfaces, implement composable redaction primitives, guarantee lossless handling of high-severity events, and expose metrics for SRE monitoring. The plan prioritizes bounded memory, async-safe operations, and fan-out resilience across distributed workers.

| file | op | functions/APIs | tests | perf/mem budget | risk |
| --- | --- | --- | --- | --- | --- |
| `logging_lib/config.py` | update | `RedactionSettings`, `SamplingSettings`, `load_config` | `tests/logging/test_config_phase4.py` | New config load ≤2 ms, no extra allocations beyond cache | Medium |
| `logging_lib/redaction/defaults.py` | add | `hash_redactor`, `truncate_redactor`, registry bootstrap | `tests/logging/test_redaction_defaults.py` | Redaction adds ≤5% CPU per event, zero heap growth per call | Medium |
| `logging_lib/redaction.py` | update | `RedactorRegistry`, `apply_redaction`, plugin registration | `tests/logging/test_redaction_registry.py` | Batch redaction stays lock-free; ≤10 µs per field | High |
| `logging_lib/sampling.py` | update | `should_log`, policy evaluators, level guards | `tests/logging/test_sampling_policies.py` | Decision latency ≤5 µs, error/critical bypass sampling | High |
| `logging_lib/queue.py` | update | `enqueue`, `emit_drop_event`, backpressure handling | `tests/logging/test_queue_drops.py` | No unbounded retries; queue memory ≤ existing cap | High |
| `logging_lib/schema.py` | update | `validate_payload`, `enforce_payload_limits` | `tests/logging/test_schema_limits.py` | Validation ≤3 µs per event; payload cap 16 KB | Medium |
| `logging_lib/metrics.py` | update | `increment_counter`, new drop/sampling gauges | `tests/logging/test_metrics_phase4.py` | Metrics updates <1 µs; no blocking I/O | Low |
| `logging_lib/facade.py` | update | `get_logger`, log API context metadata | `tests/logging/test_facade_phase4.py` | Context binding ≤10 µs; thread-safe | Medium |
| `docs/logging/integration.md` | update | Document policy tuning & rollout steps | `n/a` | n/a | Low |

**Notes:**
- Ensure redaction/sampling execution paths remain re-entrant and safe for concurrent async workers.
- Surface drop/sampling metrics via existing monitoring exporters for distributed health dashboards.

