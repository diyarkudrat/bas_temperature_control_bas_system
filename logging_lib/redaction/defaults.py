"""Builtin redaction primitives for the logging library."""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Dict


Redactor = Callable[[str, Any], Any]


def build_hash_redactor(salt: str) -> Redactor:
    """Create a redactor that replaces values with a deterministic hash."""

    namespace = salt.encode("utf-8", "ignore") if salt else b""

    def _hash_redactor(key: str, value: Any) -> str:
        payload = f"{key}:{value}".encode("utf-8", "ignore")
        hasher = hashlib.blake2b(digest_size=10, person=namespace[:16])
        hasher.update(payload)
        digest = hasher.hexdigest()
        return f"redacted:{digest}"

    return _hash_redactor


def build_truncate_redactor(max_length: int, suffix: str) -> Redactor:
    """Create a redactor that truncates long string payloads."""

    max_length = max(0, max_length)

    def _truncate_redactor(_key: str, value: Any) -> str:
        text = str(value)
        if max_length == 0 or len(text) <= max_length:
            return text
        return text[:max_length] + suffix

    return _truncate_redactor


def _mask_token(_key: str, value: Any) -> str:
    text = str(value)
    if len(text) <= 8:
        return "***"
    return f"{text[:4]}...{text[-4:]}"


def _mask_email(_key: str, value: Any) -> str:
    text = str(value)
    if "@" not in text:
        return _mask_token(_key, text)
    local, _, domain = text.partition("@")
    local_mask = local[0] + "***" if local else "***"
    return f"{local_mask}@{domain}"


def BUILTIN_FIELD_REDACTORS(
    truncate_redactor: Redactor, hash_redactor: Redactor
) -> Dict[str, Redactor]:
    """Return builtin field redactors applying tokens, hashes, and truncation."""

    return {
        "authorization": _mask_token,
        "access_token": _mask_token,
        "refresh_token": _mask_token,
        "id_token": _mask_token,
        "token": _mask_token,
        "secret": hash_redactor,
        "password": hash_redactor,
        "email": _mask_email,
        "request_body": truncate_redactor,
    }


def BUILTIN_CONTEXT_REDACTORS(hash_redactor: Redactor) -> Dict[str, Redactor]:
    """Return builtin context redactors for nested payloads."""

    return {
        "password": hash_redactor,
        "token": hash_redactor,
        "access_token": hash_redactor,
        "refresh_token": hash_redactor,
        "secret": hash_redactor,
    }


__all__ = [
    "build_hash_redactor",
    "build_truncate_redactor",
    "BUILTIN_FIELD_REDACTORS",
    "BUILTIN_CONTEXT_REDACTORS",
]

