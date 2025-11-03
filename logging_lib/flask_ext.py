"""Flask integration helpers for logging_lib."""

from __future__ import annotations

import importlib
import time
import uuid
from typing import Any, Iterable, Optional, Tuple

from flask import Flask, Response, g, request

from . import get_logger
from .config import get_settings
from .logger import pop_context, push_context


class _TraceInfo:
    def __init__(self, trace_id: Optional[str], span_id: Optional[str]) -> None:
        self.trace_id = trace_id
        self.span_id = span_id


def register_flask_context(app: Flask, *, service: str | None = None) -> None:
    """Attach request lifecycle hooks for structured logging."""

    settings = get_settings()
    component = service or settings.service
    request_id_header = settings.request_id_header
    traceparent_header = settings.traceparent_header
    capture_headers = {header.lower() for header in settings.capture_headers}
    exclude_routes = settings.exclude_routes
    logger = get_logger(f"{component}.http")

    def _should_log_route(path: str) -> bool:
        return not any(path.startswith(prefix) for prefix in exclude_routes)

    @app.before_request
    def _logging_before_request() -> None:  # type: ignore[override]
        if not _should_log_route(request.path):
            return

        g._logging_start = time.perf_counter()
        rid = (request.headers.get(request_id_header) or "").strip()
        if not rid:
            rid = uuid.uuid4().hex[:16]
        g.request_id = rid

        otel_trace = _start_opentelemetry_span(component)
        if otel_trace:
            trace_id, span_id = otel_trace.trace_id, otel_trace.span_id
        else:
            trace_header = request.headers.get(traceparent_header)
            trace_id, span_id = _parse_traceparent(trace_header)
        trace_id, span_id = _ensure_trace_ids(trace_id, span_id)

        g._logging_trace = (trace_id, span_id)

        token = push_context(
            rid=rid,
            trace_id=trace_id,
            span_id=span_id,
            method=request.method,
            path=request.path,
            ip=_client_ip(),
        )
        g._logging_token = token

    @app.after_request
    def _logging_after_request(response: Response) -> Response:  # type: ignore[override]
        if not _should_log_route(request.path):
            return response

        rid = g.get("request_id")
        trace_id, span_id = g.get("_logging_trace", (None, None))

        elapsed_ms = _elapsed_ms(g.pop("_logging_start", None))
        route = request.url_rule.rule if request.url_rule else request.path
        user_id, tenant_id = _resolve_identity()
        header_context = {
            header: request.headers.get(header)
            for header in settings.capture_headers
            if header.lower() in capture_headers
        }

        logger.info(
            "http_request",
            route=route,
            method=request.method,
            status=response.status_code,
            lat_ms=elapsed_ms,
            rid=rid,
            trace_id=trace_id,
            span_id=span_id,
            user_id=user_id,
            tenant_id=tenant_id,
            context={
                "ip": _client_ip(),
                "user_agent": request.headers.get("User-Agent"),
                **header_context,
            },
        )

        response.headers.setdefault(request_id_header, rid)
        if trace_id and span_id:
            response.headers.setdefault(
                traceparent_header,
                _format_traceparent(trace_id, span_id),
            )

        _finalize_span(response.status_code)

        token = g.pop("_logging_token", None)
        if token is not None:
            pop_context(token)
        return response

    @app.teardown_request
    def _logging_teardown(_exc: Any) -> None:  # type: ignore[override]
        token = g.pop("_logging_token", None)
        if token is not None:
            pop_context(token)
        if _exc and _should_log_route(request.path):
            rid = g.get("request_id")
            trace_id, span_id = g.get("_logging_trace", (None, None))
            elapsed_ms = _elapsed_ms(g.pop("_logging_start", None))
            status = getattr(_exc, "code", 500)
            try:
                status_code = int(status)
            except Exception:
                status_code = 500
            logger.error(
                "http_exception",
                route=request.path,
                method=request.method,
                status=status_code,
                lat_ms=elapsed_ms,
                rid=rid,
                trace_id=trace_id,
                span_id=span_id,
                context={
                    "ip": _client_ip(),
                    "exception": type(_exc).__name__,
                    "message": str(_exc),
                },
            )
        _finalize_span(None, exc=_exc)


def _parse_traceparent(header: str | None) -> Tuple[str | None, str | None]:
    if not header:
        return None, None
    parts = header.split("-")
    if len(parts) < 4:
        return None, None
    trace_id, span_id = parts[1], parts[2]
    if len(trace_id) != 32 or len(span_id) != 16:
        return None, None
    return trace_id, span_id


def _client_ip() -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def _elapsed_ms(start: float | None) -> float:
    if start is None:
        return 0.0
    return round((time.perf_counter() - start) * 1000.0, 3)


def _resolve_identity() -> Tuple[str | None, str | None]:
    session = getattr(request, "session", None)
    user_id = getattr(session, "user_id", None)
    username = getattr(session, "username", None)
    tenant_id = getattr(session, "tenant_id", None) or getattr(g, "tenant_id", None)
    # Prefer globally unique ID, fallback to username for observability
    resolved_user = str(user_id or username) if (user_id or username) else None
    return resolved_user, tenant_id


def _observability_logger():
    return get_logger("observability.tracing")


def _ensure_trace_ids(trace_id: Optional[str], span_id: Optional[str]) -> Tuple[str, str]:
    if not trace_id or len(trace_id) != 32:
        trace_id = uuid.uuid4().hex
    if not span_id or len(span_id) != 16:
        span_id = uuid.uuid4().hex[:16]
    return trace_id, span_id


def _format_traceparent(trace_id: str, span_id: str) -> str:
    return f"00-{trace_id}-{span_id}-01"


def _start_opentelemetry_span(component: Optional[str]) -> Optional[_TraceInfo]:
    otel_logger = _observability_logger()
    try:
        trace_mod = importlib.import_module("opentelemetry.trace")
        propagate_mod = importlib.import_module("opentelemetry.propagate")
        SpanKind = getattr(trace_mod, "SpanKind", None)
        if SpanKind is None:
            return None
        tracer_getter = getattr(trace_mod, "get_tracer")
        extract = getattr(propagate_mod, "extract")
    except ModuleNotFoundError:
        return None
    except Exception as exc:  # pragma: no cover
        otel_logger.warning("OpenTelemetry modules unavailable", extra={"error": str(exc)})
        return None

    span_cm = None
    try:
        headers = {key: value for key, value in request.headers.items()}
        context = extract(headers)
        tracer = tracer_getter(component or "api")
        span_cm = tracer.start_as_current_span(
            name=f"{component or 'api'}.request",
            context=context,
            kind=SpanKind.SERVER,
        )
        span = span_cm.__enter__()
        span_ctx = span.get_span_context()
        trace_id = f"{span_ctx.trace_id:032x}" if span_ctx.trace_id else None
        span_id = f"{span_ctx.span_id:016x}" if span_ctx.span_id else None
        try:
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.target", request.full_path or request.path)
            span.set_attribute("http.scheme", request.scheme)
            span.set_attribute("http.host", request.host)
            span.set_attribute("net.peer.ip", _client_ip() or "")
        except Exception:
            pass
        g._otel_span_cm = span_cm
        g._otel_span = span
        return _TraceInfo(trace_id, span_id)
    except Exception as exc:  # pragma: no cover - graceful degradation
        if span_cm is not None:
            try:
                span_cm.__exit__(type(exc), exc, exc.__traceback__)
            except Exception:
                pass
        otel_logger.warning("OpenTelemetry span setup failed", extra={"error": str(exc)})
        g.pop("_otel_span_cm", None)
        g.pop("_otel_span", None)
        return None


def _finalize_span(status_code: Optional[int], *, exc: Any = None) -> None:
    span = g.pop("_otel_span", None)
    span_cm = g.pop("_otel_span_cm", None)
    if span is None and span_cm is None:
        return

    if span is not None:
        try:
            if status_code is not None:
                span.set_attribute("http.status_code", status_code)
            span.set_attribute("http.target", request.path)
            span.set_attribute("http.method", request.method)
            status_cls, status_code_cls = _load_status_classes()
            if status_cls and status_code_cls:
                if exc is not None:
                    span.record_exception(exc)
                    span.set_status(status_cls(status_code_cls.ERROR))
                elif status_code is not None:
                    if status_code >= 500:
                        span.set_status(status_cls(status_code_cls.ERROR))
                    else:
                        span.set_status(status_cls(status_code_cls.OK))
        except Exception:  # pragma: no cover - best effort
            pass

    if span_cm is not None:
        try:
            if exc is not None:
                span_cm.__exit__(type(exc), exc, exc.__traceback__)
            else:
                span_cm.__exit__(None, None, None)
        except Exception:  # pragma: no cover
            pass


def _load_status_classes() -> Tuple[Optional[Any], Optional[Any]]:
    try:
        status_mod = importlib.import_module("opentelemetry.trace.status")
        return getattr(status_mod, "Status", None), getattr(status_mod, "StatusCode", None)
    except ModuleNotFoundError:
        return None, None
    except Exception as exc:  # pragma: no cover
        _observability_logger().warning("OpenTelemetry status classes unavailable", extra={"error": str(exc)})
        return None, None

