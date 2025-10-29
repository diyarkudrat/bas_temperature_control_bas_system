# Logging Library — Design Plan

## 1. Current State Assessment (brief)
- **Strength**: Flask API initializes Python logging uniformly, so core services already depend on the standard library entry point.
```43:45:apps/api/main.py
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
```
- **Gap**: Embedded/MicroPython path prints formatted strings synchronously; no structured output, buffering, or cloud alignment.
```141:154:src/bas/services/logging.py
        entry = LogEntry(
            timestamp_ms=time.ticks_ms(),
            level=level,
            component=self.component,
            message=message,
            data=kwargs
        )
        self._buffer.append(entry)
        if self._print_enabled:
            print(entry.format())
```
- **Gap**: No repository code generates request IDs, trace context, or JSON payloads; logs miss W3C propagation and Cloud Run conventions.
- **Anti-pattern**: Logging lives inside business modules with no redaction controls; sensitive fields (e.g., usernames in `application/auth/services.py`) are written raw via standard logging.

## 2. Proposed Architecture
```
┌────────────────────────┐
│  API / Auth / Telemetry│
└──────────┬─────────────┘
           ▼
   [Logger Facade]
           ▼
   [Context Injector]
           ▼
   [Sampler → Redactor]
           ▼
   [Async Buffer & Dispatcher]
        │              │
        ├── Cloud Logging Stdout Sink (Cloud Run ingestion)
        └── Cloud Logging API Sink (routing/labels) + optional test/file sink
```
- **Facade**: `get_logger(service, env, **kwargs)` returns structured logger with level-aware APIs.
- **Context Injector**: Flask extension captures request info, injects `rid`, route, method, status, latency, traceparent span IDs.
- **Formatter**: Builds canonical JSON document, ensures schema versioning.
- **Sampler**: Applies level-aware sampling; DEFAULT: INFO sampled, ERROR never sampled.
- **Redactor**: Normalizes payload, strips denylisted keys, applies custom redactors before buffering.
- **Async Dispatcher**: Background worker with bounded queue; serializes to JSON and writes to both Cloud Logging sinks; records metrics on drops.
- **Sinks/Adapters**: Built-in dual path—structured JSON to stdout (Cloud Run ingestion) and Google Cloud Logging API adapter for enriched routing; additional file sink only for local testing.

## 3. Log Schema (JSON)
```json
{
  "schema_version": 1,
  "ts": "2025-10-29T17:04:12.345Z",
  "level": "INFO",
  "service": "api",
  "env": "staging",
  "route": "/api/v1/tenants",
  "method": "GET",
  "status": 200,
  "lat_ms": 182.4,
  "rid": "ed7b1c31f1a74660",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "user_id": "auth0|xyz123",
  "tenant_id": "north-campus",
  "message": "tenant list", 
  "context": {
    "remaining_rate_limit": 47,
    "ip": "203.0.113.10"
  }
}
```
- Reserved keys: `ts`, `level`, `service`, `env`, `route`, `method`, `status`, `lat_ms`, `rid`, `trace_id`, `span_id`, `user_id`, `tenant_id`, `message`, `context`, `schema_version`.
- `context` accepts additional namespaced fields (e.g., `auth.*`, `db.*`); total payload capped at 16 KB.

## 4. Performance & Reliability
- **Buffering**: Lock-free ring buffer (`LOG_QUEUE_SIZE`, default 4096) feeding a background worker thread/process.
- **Dispatch cadence**: Flush every `LOG_FLUSH_MS` (default 200 ms) or when batch reaches `LOG_BATCH_SIZE` (default 64 entries).
- **Budget**: Client-side enqueue target p95 < 1 ms; verifying via benchmarks that queue operations stay <200 µs.
- **Overflow**: On queue full, drop oldest INFO/DEBUG with counter increment; WARN becomes lossless with retry for up to `LOG_SYNC_TIMEOUT_MS` (50 ms); ERROR/CRITICAL bypass queue overflow by immediate write (synchronous fallback) while emitting an internal warning if latency budget is exceeded.
- **Failures**: Sink write errors trigger exponential backoff (max 1 s) and emit synthetic ERROR log with `event=logger_failure`; dispatcher never raises into caller thread.

## 5. Security & Redaction
- Default denylist keys: `password`, `pass`, `token`, `access_token`, `refresh_token`, `authorization`, `cookie`, `session`, `ssn`, `credit_card`, `email`, `phone`, `secret`.
- Default behavior hashes (SHA-256 + 8-char prefix) for tokens and replaces emails with redacted form (`user***@domain`); values stored in redaction metadata for troubleshooting.
- Allowlist override per service (e.g., explicitly keep `email` when hashed & permitted).
- Custom redactors: register callables via `register_redactor(pattern: str, fn: Callable[[str], str])` executed before serialization.
- Policy: Identifiers are truncated, tokens never logged raw, PII inclusion requires explicit opt-in via configuration flag (`LOG_ALLOW_PII=0` default).

## 6. GCL Integration & SLO Signals
- Cloud Run ingest path: structured JSON emitted to stdout with severity mapped from `level`; Cloud Logging agent parses automatically.
- Direct Google Cloud Logging adapter: dispatcher streams batches via the official client, adds resource labels (`service`, `env`, `revision`), and guarantees delivery ordering per batch; adapter enabled by default with service-account impersonation.
- Suggested log-based metrics:
  1. **`backend/error_rate`** – filter `resource.type="cloud_run_revision" AND severity>=ERROR`.
  2. **`auth/failures`** – filter `jsonPayload.service="auth" AND jsonPayload.status=401`.
  3. **`api/latency_p95`** – distribution metric on `jsonPayload.lat_ms` with filter `jsonPayload.service="api"`.
  4. **`audit/permission_denied`** – filter `jsonPayload.context.event="PERMISSION_DENIED"`.
  5. **`queue/drops`** – filter `jsonPayload.context.event="log_drop"` severity WARNING.
- Additional sinks: BigQuery export and Cloud Storage archival can be toggled via `LOG_ADDITIONAL_SINKS`; they complement, not replace, the mandatory Cloud Logging sinks.

## 7. Flask Integration Snippets
**App factory configuration**
```python
from logging_lib import configure_logging, register_flask_context

def create_app() -> Flask:
    app = Flask(__name__)
    configure_logging(
        service="api",
        env=os.getenv("BAS_ENV", "local"),
        default_level=os.getenv("LOG_LEVEL", "INFO")
    )
    register_flask_context(app)
    return app
```

**Request middleware**
```python
import time
import uuid
from flask import g, request, Response
from logging_lib import get_logger, extract_trace_context

logger = get_logger("api")

def register_flask_context(app: Flask) -> None:
    @app.before_request
    def _start_timer() -> None:
        request._start = time.perf_counter()
        trace_ctx = extract_trace_context(request.headers.get("traceparent"))
        g.trace_id, g.span_id = trace_ctx.trace_id, trace_ctx.span_id
        g.request_id = request.headers.get("X-Request-Id") or uuid.uuid4().hex[:16]
        request.headers.setdefault("X-Request-Id", g.request_id)

    @app.after_request
    def _log_request(response: Response) -> Response:
        elapsed_ms = (time.perf_counter() - getattr(request, "_start", time.perf_counter())) * 1000
        logger.info(
            "request",
            route=request.url_rule and request.url_rule.rule,
            method=request.method,
            status=response.status_code,
            lat_ms=round(elapsed_ms, 2),
            rid=g.request_id,
            trace_id=g.trace_id,
            span_id=g.span_id,
            user_id=getattr(getattr(request, "user", None), "id", None),
            tenant_id=getattr(getattr(request, "user", None), "tenant_id", None),
            context={"ip": request.remote_addr}
        )
        response.headers["X-Request-Id"] = g.request_id
        return response
```

## 8. Configuration Matrix
| Env Var | Default | Description |
| --- | --- | --- |
| `LOG_LEVEL` | `INFO` | Minimum severity emitted. |
| `LOG_SAMPLE_RATE_INFO` | `1.0` | Fraction of INFO logs kept (0–1). |
| `LOG_SAMPLE_RATE_DEBUG` | `0.1` | Fraction of DEBUG logs kept. |
| `LOG_QUEUE_SIZE` | `4096` | Ring buffer capacity for async dispatcher. |
| `LOG_BATCH_SIZE` | `64` | Max events per flush. |
| `LOG_FLUSH_MS` | `200` | Flush interval in milliseconds. |
| `LOG_ASYNC_WORKERS` | `1` | Number of dispatcher workers. |
| `LOG_GCL_ENABLED` | `1` | When `1`, emit to Cloud Logging API in addition to stdout (must remain 1 outside tests). |
| `LOG_FILE_PATH` | `logs/app.log` | File sink path (test/dev) activated via `LOG_ADDITIONAL_SINKS`. |
| `LOG_ADDITIONAL_SINKS` | `` | Comma list (`file`, `stdout_only`) for debugging scenarios. |
| `LOG_REDACT_KEYS` | comma list of defaults | Extend denylist keys. |
| `LOG_ALLOW_PII` | `0` | When `1`, allow hashed PII fields. |
| `LOG_SERVICE_NAME` | auto-detected | Overrides service field. |
| `LOG_ENV` | `local` | Environment tag (local/staging/prod). |
| `LOG_TRACE_ENABLED` | `1` | Toggle traceparent parsing/emission. |
| `LOG_SINK_GCL_PROJECT` | inherited from env | Project for direct GCL sink. |

## 9. Trade-offs & Alternatives (succinct)
- **Stdout + Direct GCL API**: Dual path ensures Cloud Run ingestion plus enriched routing/labels; API adds slight complexity but unlocks regional sinks and log-based metrics. Default: both enabled, API may be disabled only in unit tests.
- **Async vs Sync**: Async adds complexity but keeps hot path <1 ms and shields from sink outages; sync would simplify but risk Cloud Run latency spikes. Default: async.
- **Library vs Sidecar**: Embedded library eases adoption and preserves request context; sidecar would require network hops and shared protocol. Default: single library with pluggable sinks.
- **Sampling defaults**: INFO sampled (1.0) with dynamic control; DEBUG heavily sampled to contain cost. ERROR never sampled.

## 10. Minimal API Sketch
```python
from logging_lib import get_logger, logger_context

logger = get_logger(service="auth", env="staging")

logger.info("auth_success", user_id="auth0|abc", tenant_id="west")

with logger_context(rid="abc123", trace_id=trace_id, span_id=span_id):
    logger.warning("rate_limit_shadow", route="/api/data", remaining=3)

class SinkAdapter(Protocol):
    def emit(self, records: list[dict[str, Any]]) -> None: ...

register_sink("gcl", GclSinkAdapter(credentials_path))
```

