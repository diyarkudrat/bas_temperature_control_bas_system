# Phase 1 Patch Plan — Core Library Bootstrap

## Summary
Lay down the initial `logging_lib` package with module scaffolding, JSON schema utilities, configuration loader, logging facade backed by an in-memory queue, and baseline sinks/documentation. Output is a working library skeleton ready for Cloud Logging integration in later phases.

## File/Module Operations
| File/Module | Operation | Notes |
| --- | --- | --- |
| `logging_lib/__init__.py` | Add | Expose public API (`get_logger`, `logger_context`, `configure`, constants). |
| `logging_lib/config.py` | Add | Load settings from env/file/defaults; define dataclass for configuration. |
| `logging_lib/schema.py` | Add | Define canonical JSON structure, validation helpers, reserved key enforcement, schema version constant. |
| `logging_lib/redaction.py` | Add | Stub redaction registry (no-op implementations but interfaces defined). |
| `logging_lib/sampling.py` | Add | Stub sampling decisions (default pass-through). |
| `logging_lib/queue.py` | Add | Simple thread-safe queue/in-memory buffer abstraction. |
| `logging_lib/sinks/stdout.py` | Add | Placeholder sink that writes structured JSON to stdout. |
| `logging_lib/sinks/memory.py` | Add | In-memory sink for tests (collects records). |
| `logging_lib/logger.py` | Add | Implement facade, logger class, context manager, integration with queue and sinks. |
| `logging_lib/dispatcher.py` | Add | Synchronous dispatcher stub that drains queue (placeholder for async later). |
| `docs/logging/README.md` | Add | Document package layout, public API, Phase 1 capabilities/limitations. |
| `pyproject.toml` / `setup.cfg` | Update | Ensure package discovery and dependencies (if needed). |
| `tests/logging/test_schema.py` | Add | Smoke tests for schema validation (if tests desired; optional per instructions). |

## Implementation Steps
1. **Package scaffolding**
   - Create `logging_lib/` directory with `__init__.py` exporting configuration and facade helpers.
   - Establish subpackages `sinks/` and modules per table above.

2. **Configuration loader**
   - Implement dataclass `LoggingSettings` with fields: `service`, `env`, `level`, queue size, batch size, sinks list, etc. (values from design plan; defaults set for Phase 1).
   - Provide `load_settings()` reading env vars and optional config file (YAML/JSON) with merge precedence (env overrides file). For now, file reading can be stub or limited to env variables.
   - Expose `configure(settings: LoggingSettings | None)` to set global configuration state.

3. **Schema utilities**
   - Implement `build_log_record(...)` taking message, level, context fields, injecting `schema_version`, `ts` (UTC ISO timestamp), default `service/env` from settings.
   - Add `validate_record(record: dict)` to enforce reserved keys exist and no forbidden keys.

4. **Queue & dispatcher**
   - Introduce simple queue (e.g., `collections.deque` with `threading.Lock`) to buffer log entries.
   - Dispatcher `flush()` drains queue synchronously and publishes to registered sinks (stdout + memory sink optional). Async behavior will come in Phase 2, but interfaces should anticipate it.

5. **Logger facade**
   - Implement `Logger` class with `debug/info/warning/error/critical`, each building structured record via schema utilities, passing through redaction/sampling (currently no-ops), and enqueuing into dispatcher.
   - Provide context manager (`logger_context`) storing contextual metadata (rid/trace/span) to merge into each record.
   - Global registry mapping `service` names to `Logger` instances using current configuration.

6. **Baseline sinks**
   - Stdout sink: JSON-serialize records using `json.dumps`, ensure newline-delimited output (NDJSON) for Cloud Run ingestion later.
   - In-memory sink: store records in list for debugging/tests.

7. **Documentation**
   - Draft `docs/logging/README.md` describing Phase 1 architecture, module layout, configuration options, and next steps (future phases).

## Acceptance Criteria
- Importing `logging_lib` allows calling `configure()` and obtaining a logger via `get_logger(service="api")` that writes structured JSON to stdout.
- Logs include required schema fields (`schema_version`, `ts`, `service`, `env`, `level`, `message`, etc.) even if some are placeholder until later phases.
- Configuration defaults are documented, with ability to override via environment variables at runtime.
- Codebase contains clear TODO markers for Phase 2 enhancements (async dispatcher, Cloud Logging adapters).

