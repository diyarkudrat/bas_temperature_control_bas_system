"""Shared base utilities for request/response schemas."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Tuple, Type, TypeVar


class SchemaValidationError(ValueError):
    """Raised when a payload fails schema validation."""

    def __init__(self, message: str, *, errors: Optional[Iterable[str]] = None) -> None:
        detail = "; ".join(errors or [])
        super().__init__(f"{message}: {detail}" if detail else message)
        self.errors = tuple(errors or ())


T = TypeVar("T", bound="BaseSchema")


@dataclass(slots=True)
class BaseSchema:
    """Dataclass base providing convenience helpers."""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls: Type[T], payload: Mapping[str, Any] | MutableMapping[str, Any]) -> T:
        try:
            return cls(**dict(payload))  # type: ignore[arg-type]
        except TypeError as exc:  # pragma: no cover - initialization errors bubble
            raise SchemaValidationError("Invalid schema fields", errors=[str(exc)]) from exc


def require_field(value: Any, field: str, *, predicate: Optional[Any] = None) -> Any:
    if value is None or (isinstance(value, str) and not value.strip()):
        raise SchemaValidationError(f"Missing required field '{field}'")
    if predicate and not predicate(value):
        raise SchemaValidationError(f"Field '{field}' failed validation")
    return value


def optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        trimmed = value.strip()
        return trimmed or None
    raise SchemaValidationError("Expected string value")


def _is_email(value: str) -> bool:
    if "@" not in value or value.startswith("@") or value.endswith("@"):
        return False
    local, _, domain = value.partition("@")
    if "." not in domain:
        return False
    return all(part.strip() for part in (local, domain))


def ensure_email(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise SchemaValidationError(f"Field '{field}' must be a string")
    candidate = value.strip().lower()
    if not candidate:
        raise SchemaValidationError(f"Field '{field}' is required")
    if not _is_email(candidate):
        raise SchemaValidationError(f"Field '{field}' must be a valid email")
    return candidate


def ensure_plan(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SchemaValidationError("Plan must be a string if provided")
    normalized = value.strip().lower()
    return normalized or None


def ensure_tags(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set)):
        tags: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise SchemaValidationError("Device tags must be strings")
            tag = item.strip()
            if tag:
                tags.append(tag)
        return tuple(tags)
    raise SchemaValidationError("Device tags must be a sequence")


__all__ = [
    "BaseSchema",
    "SchemaValidationError",
    "ensure_email",
    "ensure_plan",
    "ensure_tags",
    "optional_str",
    "require_field",
]


