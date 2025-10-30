# Phase 3 Patch Plan — Flask Integration & Context Propagation

## Summary
Integrate `logging_lib` with Flask services to guarantee request-scoped context (request IDs, trace/span IDs, Auth0 identity) and structured access logs. Extend context helpers for background jobs and document adoption for API/Auth/Telemetry services.

## File/Module Operations
| File/Module | Operation | Notes |
| --- | --- | --- |
| `logging_lib/flask_ext.py` | Add | Flask blueprint/extension exposing `register_flask_context(app)` and response logging middleware. |
| `logging_lib/context.py` | Add | Helpers for propagating context into Celery/async/background jobs (extract/inject trace/tenant/user information). |
| `logging_lib/logger.py` | Update | Expose APIs for external context injection (e.g., `push_context`, `pop_context`) for non-Flask callers. |
| `logging_lib/config.py` | Update | Add knobs for Flask integration (e.g., `LOG_CAPTURE_HEADERS`, `LOG_EXCLUDE_ROUTES`, `LOG_REQUEST_BODY_LIMIT`). |
| `logging_lib/redaction.py` | Update | Include default redactors for Auth0 tokens, Authorization headers, IP addresses via configuration. |
| `logging_lib/sinks/stdout.py` | Update | Ensure HTTP-specific fields (`route`, `method`, `status`, `lat_ms`, `rid`) get serialized consistently. |
| `apps/api/main.py` | Update | Wire `register_flask_context(app)` during app factory creation; configure logging via `logging_lib.configure()`. |
| `apps/auth_service/main.py` | Update | Same as above for auth service. |
| `application/telemetry` or background job entry points | Update | Use context helpers for job executions, set service component names. |
| `docs/logging/README.md` | Update | Add integration instructions for Flask/context helpers. |
| `docs/logging/operations.md` | Update | Document request logging fields, trace propagation, common troubleshooting (missing headers). |

## Implementation Steps
1. **Flask Middleware**
   - Implement `register_flask_context(app, *, service=None)` to:
     - Generate `X-Request-Id` (UUID) when missing; attach to request/response.
     - Parse `traceparent` header using `opentelemetry.trace` utilities when available; set `trace_id`/`span_id` in logging context.
     - Capture start time in `before_request`, compute `lat_ms` in `after_request` and log a structured access event with route/method/status/ip/user/tenant.
     - Enforce non-blocking logging by using existing async dispatcher; ensure middleware handles exceptions (log ERROR with stack info) without leaking secrets.

2. **Auth0 Identity Extraction**
   - Provide helper that extracts user/tenant IDs from Flask `g` or request (leveraging existing auth middleware) while applying redaction on email/usernames per design plan.
   - Ensure tokens/PII are hashed/truncated using redaction registry.

3. **Background Context Helpers**
   - Add `logging_lib.context` with utilities: `get_current_context()`, `bind_context(**fields)`, `run_with_context(context, func, *args)` for background jobs or threads.
   - Integrate in telemetry or worker entry points so scheduled jobs propagate trace/request IDs when spawned from Flask handlers.

4. **Configuration Enhancements**
   - Support env vars: `LOG_CAPTURE_HEADERS` (comma list), `LOG_EXCLUDE_ROUTES` (regex), `LOG_REQUEST_BODY_LIMIT` (bytes) for optional logging of payload metadata (never body contents by default).
   - Document safe usage; default to capturing minimal metadata (method, route, status, latency, remote IP).

5. **Documentation**
   - Update README with sample Flask integration snippet, explanation of context fields emitted, and mention of optional header capture.
   - Extend operations guide with request logging troubleshooting, sample `gcloud logging read` queries by request ID and trace ID.

## Acceptance Criteria
- Flask API and auth services use `logging_lib` middleware, producing structured access logs with required schema fields (`route`, `method`, `status`, `lat_ms`, `rid`, `trace_id`, `span_id`, `user_id`, `tenant_id`).
- Request IDs propagate via `X-Request-Id` response header; traces correlate with Cloud Logging entries through `logging.googleapis.com/trace`.
- Errors within Flask handlers emit structured ERROR logs with context but without sensitive data.
- Background telemetry/worker jobs leverage context helpers to maintain trace continuity when spawned from HTTP workflows.
- Documentation accurately reflects setup steps and configuration options.

