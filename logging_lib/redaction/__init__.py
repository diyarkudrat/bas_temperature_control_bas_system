"""Deterministic redaction subsystem for structured logging."""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from threading import RLock
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping

from ..config import RedactionSettings
from ..metrics import record_redaction
from .defaults import (
    BUILTIN_FIELD_REDACTORS,
    BUILTIN_CONTEXT_REDACTORS,
    build_hash_redactor,
    build_truncate_redactor,
)


LOGGER = logging.getLogger("logging_lib.redaction")

Redactor = Callable[[str, Any], Any]


_GLOBAL_FIELD_REDACTORS: Dict[str, Redactor] = {}
_GLOBAL_CONTEXT_REDACTORS: Dict[str, Redactor] = {}


def _normalize_key(key: str) -> str:
    return key.lower()


@dataclass
class RedactorRegistry:
    """Thread-safe registry of redaction callables."""

    enabled: bool
    allowlist: tuple[str, ...]
    strict: bool
    _field_redactors: MutableMapping[str, Redactor]
    _context_redactors: MutableMapping[str, Redactor]
    _fallback: Redactor | None
    _lock: RLock

    def register(self, key: str, fn: Redactor, *, context: bool = False) -> None:
        """Register a redactor for a field or context key."""

        normalized = _normalize_key(key)
        with self._lock:
            if context:
                self._context_redactors[normalized] = fn
            else:
                self._field_redactors[normalized] = fn

    def register_many(
        self, entries: Mapping[str, Redactor], *, context: bool = False
    ) -> None:
        for key, fn in entries.items():
            self.register(key, fn, context=context)

    def apply(self, record: Mapping[str, Any]) -> Dict[str, Any]:
        """Redact sensitive fields from a structured record."""

        if not self.enabled:
            return dict(record)

        with self._lock:
            field_redactors = dict(self._field_redactors)
            context_redactors = dict(self._context_redactors)
            fallback = self._fallback
            allowlist = self.allowlist

        sanitized: Dict[str, Any] = {}
        redacted_count = 0

        for key, value in record.items():
            if key == "context" and isinstance(value, Mapping):
                sanitized_context: Dict[str, Any] = {}
                for ctx_key, ctx_value in value.items():
                    redactor = context_redactors.get(_normalize_key(ctx_key)) or field_redactors.get(
                        _normalize_key(ctx_key)
                    )
                    sanitized_value, was_redacted = self._apply_redactor(
                        ctx_key, ctx_value, redactor or fallback, allowlist
                    )
                    if was_redacted:
                        redacted_count += 1
                    sanitized_context[ctx_key] = sanitized_value

                sanitized["context"] = sanitized_context
                continue

            redactor = field_redactors.get(_normalize_key(key))
            sanitized_value, was_redacted = self._apply_redactor(
                key, value, redactor or fallback, allowlist
            )
            if was_redacted:
                redacted_count += 1
            sanitized[key] = sanitized_value

        if redacted_count:
            record_redaction(redacted_count)

        return sanitized

    # --------------------- internal helpers ---------------------
    def _apply_redactor(
        self,
        key: str,
        value: Any,
        candidate: Redactor | None,
        allowlist: tuple[str, ...],
    ) -> tuple[Any, bool]:
        if candidate is None or _normalize_key(key) in allowlist:
            return value, False

        try:
            return candidate(key, value), True
        except Exception:  # pragma: no cover - safety net
            LOGGER.exception("Redaction failure for key %s", key)
            if self.strict:
                raise
            return value, False


def build_registry(settings: RedactionSettings) -> RedactorRegistry:
    """Construct a registry derived from runtime settings."""

    truncate_redactor = build_truncate_redactor(
        settings.max_field_length, settings.truncate_suffix
    )
    hash_redactor = build_hash_redactor(settings.hash_salt)

    field_redactors: MutableMapping[str, Redactor] = {
        _normalize_key(field): fn
        for field, fn in BUILTIN_FIELD_REDACTORS(truncate_redactor, hash_redactor).items()
    }
    context_redactors: MutableMapping[str, Redactor] = {
        _normalize_key(field): fn
        for field, fn in BUILTIN_CONTEXT_REDACTORS(hash_redactor).items()
    }

    for field in settings.denylist:
        field_redactors[_normalize_key(field)] = hash_redactor

    for field in settings.context_denylist:
        context_redactors[_normalize_key(field)] = hash_redactor

    for field in settings.truncate_fields:
        field_redactors[_normalize_key(field)] = truncate_redactor

    allowlist = tuple(_normalize_key(field) for field in settings.allowlist)
    for field in allowlist:
        field_redactors.pop(field, None)
        context_redactors.pop(field, None)
    registry = RedactorRegistry(
        enabled=settings.enabled,
        allowlist=allowlist,
        strict=settings.strict,
        _field_redactors=field_redactors,
        _context_redactors=context_redactors,
        _fallback=hash_redactor if settings.strict else None,
        _lock=RLock(),
    )

    registry.register_many(_GLOBAL_FIELD_REDACTORS)
    registry.register_many(_GLOBAL_CONTEXT_REDACTORS, context=True)

    if settings.custom_module:
        _bootstrap_custom_module(settings.custom_module, registry)

    return registry


def _bootstrap_custom_module(path: str, registry: RedactorRegistry) -> None:
    try:
        module = importlib.import_module(path)
    except Exception:  # pragma: no cover - defensive
        LOGGER.exception("Failed to import custom redaction module %s", path)
        return

    hook = getattr(module, "register_redactors", None)
    if callable(hook):
        try:
            hook(registry)
        except Exception:  # pragma: no cover - defensive
            LOGGER.exception("Custom redaction module %s registration failed", path)


def register_redactor(key: str, fn: Redactor, *, context: bool = False) -> None:
    """Register a global redactor applied to future registries."""

    normalized = _normalize_key(key)
    if context:
        _GLOBAL_CONTEXT_REDACTORS[normalized] = fn
    else:
        _GLOBAL_FIELD_REDACTORS[normalized] = fn


__all__ = [
    "RedactorRegistry",
    "build_registry",
    "register_redactor",
]

