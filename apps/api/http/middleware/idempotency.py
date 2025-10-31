"""Idempotency middleware for write endpoints.

This module provides a decorator that enforces the presence of an
``Idempotency-Key`` header (configurable) and persists request outcomes so
retries return the original response instead of re-executing the handler.

The default storage engine is an in-memory TTL cache suitable for local
development. The design intentionally isolates storage interactions so a future
Firestore-backed implementation can replace ``InMemoryIdempotencyStore``
without touching the decorator contract.
"""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple

from flask import Response, current_app, jsonify, make_response, request

from logging_lib import get_logger as get_structured_logger


logger = get_structured_logger("api.http.middleware.idempotency")


_DEFAULT_HEADER = "Idempotency-Key"
_REPLAY_HEADER = "Idempotent-Replay"
_PERSISTED_HEADERS: Iterable[str] = ("Content-Type", "Content-Encoding", "Content-Language")


@dataclass
class IdempotencyEntry:
    status: str  # "in_progress" | "completed"
    method: str
    path: str
    tenant_id: Optional[str]
    created_at: float
    expires_at: float
    status_code: Optional[int] = None
    body_base64: Optional[str] = None
    headers: Optional[Dict[str, str]] = None


class InMemoryIdempotencyStore:
    """Thread-safe, TTL-based idempotency store."""

    def __init__(self, ttl_seconds: int = 24 * 3600) -> None:
        self._ttl_seconds = max(60, int(ttl_seconds))
        self._entries: Dict[str, IdempotencyEntry] = {}
        self._lock = threading.RLock()

    def _purge_expired(self, now: float) -> None:
        expired = [key for key, entry in self._entries.items() if entry.expires_at <= now]
        for key in expired:
            self._entries.pop(key, None)

    def reserve(self, key: str, *, method: str, path: str, tenant_id: Optional[str]) -> Tuple[str, IdempotencyEntry]:
        now = time.monotonic()
        with self._lock:
            self._purge_expired(now)
            entry = self._entries.get(key)
            if entry:
                return entry.status, entry
            expires_at = now + self._ttl_seconds
            entry = IdempotencyEntry(
                status="in_progress",
                method=method,
                path=path,
                tenant_id=tenant_id,
                created_at=now,
                expires_at=expires_at,
            )
            self._entries[key] = entry
            return "reserved", entry

    def record_response(
        self,
        key: str,
        *,
        status_code: int,
        body_base64: str,
        headers: Dict[str, str],
    ) -> None:
        with self._lock:
            entry = self._entries.get(key)
            if not entry:
                return
            entry.status = "completed"
            entry.status_code = status_code
            entry.body_base64 = body_base64
            entry.headers = headers

    def release(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)


def _get_store() -> InMemoryIdempotencyStore:
    store = current_app.config.get("idempotency_store")
    if isinstance(store, InMemoryIdempotencyStore):
        return store
    store = InMemoryIdempotencyStore()
    current_app.config["idempotency_store"] = store
    return store


def _hash_key(raw_key: str, *, method: str, path: str, tenant_id: Optional[str]) -> str:
    material = "||".join([raw_key.strip(), method.upper(), path, tenant_id or "-"])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return digest


def _store_headers(response: Response) -> Dict[str, str]:
    captured: Dict[str, str] = {}
    for header in _PERSISTED_HEADERS:
        if header in response.headers:
            captured[header] = response.headers[header]
    return captured


def _build_response_from_entry(entry: IdempotencyEntry) -> Response:
    if entry.status_code is None or entry.body_base64 is None:
        # Gracefully degrade to 202 replay if incomplete.
        resp = jsonify({"status": "pending"})
        resp.status_code = 202
        return resp

    body_bytes = base64.b64decode(entry.body_base64.encode("ascii")) if entry.body_base64 else b""
    response = current_app.response_class(body_bytes, status=entry.status_code)
    if entry.headers:
        for key, value in entry.headers.items():
            response.headers[key] = value
    response.headers[_REPLAY_HEADER] = "true"
    return response


def enforce_idempotency(header_name: str = _DEFAULT_HEADER, methods: Tuple[str, ...] = ("POST", "PUT", "PATCH")):
    """Decorator enforcing idempotent behavior for mutating endpoints."""

    normalized_methods = tuple(m.upper() for m in methods)

    def decorator(func):
        def _inner(*args, **kwargs):
            if request.method.upper() not in normalized_methods:
                return func(*args, **kwargs)

            provided_key = request.headers.get(header_name)
            if not provided_key or not provided_key.strip():
                logger.warning("Missing idempotency key", extra={"endpoint": request.endpoint})
                return jsonify({
                    "error": "Idempotency key required",
                    "code": "IDEMPOTENCY_KEY_MISSING",
                }), 400

            tenant_id = getattr(request, "tenant_id", None)
            hashed_key = _hash_key(provided_key, method=request.method, path=request.path, tenant_id=tenant_id)
            store = _get_store()
            status, entry = store.reserve(
                hashed_key,
                method=request.method,
                path=request.path,
                tenant_id=tenant_id,
            )

            if status == "completed":
                logger.info(
                    "Idempotent replay",
                    extra={"endpoint": request.endpoint, "tenant": tenant_id},
                )
                return _build_response_from_entry(entry)

            if status == "in_progress":
                logger.info(
                    "Idempotent request already in progress",
                    extra={"endpoint": request.endpoint, "tenant": tenant_id},
                )
                return jsonify({
                    "error": "Request already in progress",
                    "code": "REQUEST_IN_PROGRESS",
                }), 409

            try:
                response = make_response(func(*args, **kwargs))
            except Exception:
                store.release(hashed_key)
                raise

            try:
                body_bytes = response.get_data()
                body_base64 = base64.b64encode(body_bytes).decode("ascii") if body_bytes else ""
            except Exception:
                body_base64 = ""

            headers = _store_headers(response)
            store.record_response(
                hashed_key,
                status_code=response.status_code,
                body_base64=body_base64,
                headers=headers,
            )
            response.headers.setdefault("Idempotency-Key", provided_key)
            return response

        _inner.__name__ = getattr(func, "__name__", "idempotent_wrapped")
        _inner.__doc__ = getattr(func, "__doc__")
        return _inner

    return decorator


__all__ = [
    "InMemoryIdempotencyStore",
    "enforce_idempotency",
]


