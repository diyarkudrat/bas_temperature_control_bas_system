"""Flask integration helpers for logging_lib."""

from __future__ import annotations

import time
import uuid
from typing import Any, Iterable, Tuple

from flask import Flask, Response, g, request

from . import get_logger
from .config import get_settings
from .logger import get_context, pop_context, push_context


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

        trace_header = request.headers.get(traceparent_header)
        trace_id, span_id = _parse_traceparent(trace_header)
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

