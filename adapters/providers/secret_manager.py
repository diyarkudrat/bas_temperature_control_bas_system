"""Secret Manager adapter with graceful local fallback.

This module provides a small abstraction over Google Cloud Secret Manager that
is safe to import even when the dependency or project configuration is
missing. The adapter follows a boundary-first approach so callers can provide
mock clients during tests while production code can rely on ADC credentials
and env configuration.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:  # pragma: no cover - optional dependency
    from google.api_core import exceptions as gcloud_exceptions  # type: ignore
    from google.cloud import secretmanager  # type: ignore
except Exception:  # pragma: no cover - import guard for environments without GCP libs
    gcloud_exceptions = None
    secretmanager = None


logger = logging.getLogger(__name__)


class SecretManagerError(RuntimeError):
    """Raised when secret storage fails."""


@dataclass(frozen=True)
class StoredSecret:
    """Represents a stored secret reference."""

    reference: str
    secret_id: str
    created_at: float


class SecretManagerAdapter:
    """Thin wrapper that handles real Secret Manager and local fallback."""

    def __init__(
        self,
        project_id: Optional[str],
        *,
        client: Optional[Any] = None,
        fallback_prefix: str = "local",
    ) -> None:
        self._project_id = (project_id or os.getenv("GOOGLE_CLOUD_PROJECT") or "").strip()
        self._client = client
        if self._client is None and secretmanager is not None and self._project_id:
            try:  # pragma: no cover - exercise in integration environments
                self._client = secretmanager.SecretManagerServiceClient()
            except Exception:  # pragma: no cover - best effort initialization
                logger.warning("Secret Manager client initialization failed; falling back to in-memory store", exc_info=True)
                self._client = None
        self._fallback_prefix = fallback_prefix.rstrip(":")
        self._fallback_store: Dict[str, bytes] = {}
        self._lock = threading.RLock()

    @property
    def project_id(self) -> Optional[str]:
        return self._project_id or None

    def store_secret(
        self,
        *,
        secret_id: str,
        payload: bytes,
        labels: Optional[Dict[str, str]] = None,
    ) -> StoredSecret:
        """Persist secret bytes and return a stable reference."""

        normalized_id = secret_id.strip().replace(" ", "-")
        if not normalized_id:
            raise SecretManagerError("secret_id is required")

        # Prefer managed secret manager when available.
        if self._client is not None and self._project_id:
            parent = f"projects/{self._project_id}"
            secret_name = f"{parent}/secrets/{normalized_id}"
            try:  # pragma: no cover - requires live service or emulator
                self._client.get_secret(name=secret_name)
            except Exception as exc:  # pragma: no cover - handled to create lazily
                if gcloud_exceptions and isinstance(exc, gcloud_exceptions.NotFound):
                    self._create_secret(secret_name=secret_name, secret_id=normalized_id, parent=parent, labels=labels)
                elif gcloud_exceptions and isinstance(exc, gcloud_exceptions.PermissionDenied):
                    logger.warning("Secret Manager access denied; using in-memory fallback", exc_info=True)
                    return self._store_fallback(normalized_id, payload)
                else:
                    logger.warning("Secret lookup failed; attempting to create secret", exc_info=True)
                    self._create_secret(secret_name=secret_name, secret_id=normalized_id, parent=parent, labels=labels)

            try:  # pragma: no cover - requires live service or emulator
                version = self._client.add_secret_version(
                    parent=secret_name,
                    payload={"data": payload},
                )
                return StoredSecret(reference=version.name, secret_id=normalized_id, created_at=time.time())
            except Exception as exc:  # pragma: no cover - degrade gracefully
                logger.error("Failed to add secret version; falling back to in-memory store", exc_info=True)
                return self._store_fallback(normalized_id, payload)

        return self._store_fallback(normalized_id, payload)

    def generate_secret_id(self, *, tenant_id: str, device_id: str) -> str:
        random_suffix = secrets.token_hex(6)
        return f"device-{tenant_id}-{device_id}-{random_suffix}".lower()

    def get_fallback_secret(self, reference: str) -> Optional[bytes]:
        with self._lock:
            return self._fallback_store.get(reference)

    def _create_secret(
        self,
        *,
        secret_name: str,
        secret_id: str,
        parent: str,
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        if self._client is None:
            return
        try:  # pragma: no cover - requires live service or emulator
            self._client.create_secret(
                parent=parent,
                secret_id=secret_id,
                secret={
                    "replication": {"automatic": {}},
                    "labels": labels or {},
                },
            )
        except Exception:  # pragma: no cover - ignore if existing or failing
            logger.debug("Secret creation skipped or failed", exc_info=True)

    def _store_fallback(self, secret_id: str, payload: bytes) -> StoredSecret:
        with self._lock:
            reference = f"{self._fallback_prefix}://{secret_id}-{secrets.token_hex(4)}"
            self._fallback_store[reference] = payload
            logger.info(
                "Stored secret material in fallback store",
                extra={"reference": reference, "secret_id": secret_id},
            )
            return StoredSecret(reference=reference, secret_id=secret_id, created_at=time.time())


__all__ = [
    "SecretManagerAdapter",
    "SecretManagerError",
    "StoredSecret",
]


