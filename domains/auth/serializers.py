"""Serialization helpers for auth domain models.

These helpers convert pure domain dataclasses to and from storage-oriented
payloads. They intentionally live outside the dataclasses so the shared kernel
remains side-effect free.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Mapping

from .models import Session, User

logger = logging.getLogger(__name__)


def user_to_dict(user: User) -> dict[str, Any]:
    """Convert a :class:`User` into a storage dictionary."""

    logger.debug("Serializing user %%s", user.username)
    payload: dict[str, Any] = {
        "username": user.username,
        "password_hash": user.password_hash,
        "salt": user.salt,
        "role": user.role,
        "created_at": user.created_at,
        "last_login": user.last_login,
        "failed_attempts": user.failed_attempts,
        "locked_until": user.locked_until,
        "password_history": json.dumps(list(user.password_history)),
    }
    return payload


def user_from_dict(data: Mapping[str, Any]) -> User:
    """Create a :class:`User` from a storage dictionary."""

    logger.debug("Deserializing user %s", data.get("username", "unknown"))
    password_history_raw = data.get("password_history", "[]")
    password_history = _safe_json_list(password_history_raw)

    created_at = _coerce_number(data.get("created_at"), default=time.time())
    last_login = _coerce_number(data.get("last_login"), default=0)
    failed_attempts = _coerce_int(data.get("failed_attempts"), default=0)
    locked_until = _coerce_number(data.get("locked_until"), default=0)

    role = data.get("role", "operator")
    if role not in {"operator", "admin", "read-only"}:
        role = "operator"

    return User(
        username=str(data["username"]),
        password_hash=str(data["password_hash"]),
        salt=str(data["salt"]),
        role=str(role),
        created_at=created_at,
        last_login=last_login,
        failed_attempts=failed_attempts,
        locked_until=locked_until,
        password_history=password_history,
    )


def session_to_dict(session: Session) -> dict[str, Any]:
    """Convert a :class:`Session` into a storage dictionary."""

    logger.debug("Serializing session %%s", session.session_id)
    payload: dict[str, Any] = {
        "session_id": session.session_id,
        "username": session.username,
        "role": session.role,
        "created_at": session.created_at,
        "expires_at": session.expires_at,
        "last_access": session.last_access,
        "fingerprint": session.fingerprint,
        "ip_address": session.ip_address,
        "user_agent": session.user_agent,
        "user_id": session.user_id,
        "tenant_id": session.tenant_id,
    }
    return payload


def session_from_dict(data: Mapping[str, Any]) -> Session:
    """Create a :class:`Session` from a storage dictionary."""

    logger.debug("Deserializing session %s", data.get("session_id", "unknown"))
    created_at = _coerce_number(data.get("created_at"), default=time.time())
    expires_at_default = created_at + 1800
    expires_at = _coerce_number(data.get("expires_at"), default=expires_at_default)
    if expires_at < created_at:
        expires_at = expires_at_default
    last_access = _coerce_number(data.get("last_access"), default=created_at)
    if last_access < created_at:
        last_access = created_at

    role = data.get("role", "operator")
    if role not in {"operator", "admin", "read-only"}:
        role = "operator"

    return Session(
        session_id=str(data["session_id"]),
        username=str(data["username"]),
        role=str(role),
        created_at=created_at,
        expires_at=expires_at,
        last_access=last_access,
        fingerprint=str(data["fingerprint"]),
        ip_address=str(data["ip_address"]),
        user_agent=str(data["user_agent"]),
        user_id=str(data.get("user_id", "unknown")),
        tenant_id=data.get("tenant_id"),
    )


def _coerce_number(value: Any, *, default: float) -> float:
    try:
        if isinstance(value, (int, float)):
            if value >= 0:
                return float(value)
            return float(default)
        if value is None:
            return float(default)
        numeric = float(value)
        return numeric if numeric >= 0 else float(default)
    except Exception:
        return float(default)


def _coerce_int(value: Any, *, default: int) -> int:
    try:
        if isinstance(value, int) and value >= 0:
            return value
        numeric = int(value)
        return numeric if numeric >= 0 else default
    except Exception:
        return default


def _safe_json_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    try:
        parsed = json.loads(value)  # type: ignore[arg-type]
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    except Exception:
        pass
    return []


__all__ = [
    "user_to_dict",
    "user_from_dict",
    "session_to_dict",
    "session_from_dict",
]

