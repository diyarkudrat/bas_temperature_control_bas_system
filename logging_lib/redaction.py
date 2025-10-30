"""Redaction helpers for structured logging."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping


Redactor = Callable[[str, Any], Any]


@dataclass
class RedactionRegistry:
    """Registry of per-field redaction callables."""

    _redactors: Dict[str, Redactor] = field(default_factory=dict)

    def register(self, key: str, fn: Redactor) -> None:
        """Register a redaction function for a given key."""

        self._redactors[key] = fn

    def apply(self, record: Mapping[str, Any]) -> Dict[str, Any]:
        """Apply redaction to a record."""

        sanitized = dict(record)
        context = sanitized.get("context")

        if isinstance(context, dict):
            sanitized["context"] = {
                k: self._redactors[k](k, v) if k in self._redactors else v
                for k, v in context.items()
            }

        for key, redactor in self._redactors.items():
            if key in sanitized and key != "context":
                sanitized[key] = redactor(key, sanitized[key])

        return sanitized


_REGISTRY = RedactionRegistry()


def register_redactor(key: str, fn: Redactor) -> None:
    """Register a redaction function for a given key."""

    _REGISTRY.register(key, fn)


def apply_redaction(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Apply redaction to a record."""
    
    return _REGISTRY.apply(record)

def _mask_token(_key: str, value: Any) -> str:
    text = str(value)
    if len(text) <= 8:
        return "***"
    return f"{text[:4]}…{text[-4:]}"


def _mask_email(_key: str, value: Any) -> str:
    text = str(value)
    if "@" not in text:
        return _mask_token(_key, text)
    local, _, domain = text.partition("@")
    masked_local = local[0] + "***" if local else "***"
    return f"{masked_local}@{domain}"


for _key, _fn in {
    "authorization": _mask_token,
    "access_token": _mask_token,
    "refresh_token": _mask_token,
    "id_token": _mask_token,
    "token": _mask_token,
    "email": _mask_email,
}.items():
    register_redactor(_key, _fn)

