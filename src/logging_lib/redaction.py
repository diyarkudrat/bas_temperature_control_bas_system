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


