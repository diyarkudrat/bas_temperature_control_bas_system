"""Device credential management service."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Mapping, MutableMapping, Optional

from adapters.providers.secret_manager import SecretManagerAdapter, StoredSecret


@dataclass(frozen=True)
class DeviceCredentialRecord:
    """Record returned when issuing device credentials."""

    credential_reference: str
    secret_id: str
    rotation_due_at: int


class DeviceCredentialService:
    """Facade responsible for issuing and scheduling credential rotations."""

    __slots__ = ("__secret_manager", "__rotation_seconds", "__namespace")

    def __init__(
        self,
        secret_manager: SecretManagerAdapter,
        *,
        rotation_hours: int = 24 * 30,
        namespace: str = "device",
    ) -> None:
        """Initialize the DeviceCredentialService."""

        self.__secret_manager = secret_manager
        self.__rotation_seconds = max(3600, int(rotation_hours * 3600))
        self.__namespace = namespace.strip().lower() or "device"

    def issue_credentials(
        self,
        *,
        tenant_id: str,
        device_id: str,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> DeviceCredentialRecord:
        """Issue credentials for a device."""

        payload = self.__generate_secret_material()
        secret_id = self.__build_secret_id(tenant_id=tenant_id, device_id=device_id)
        labels: MutableMapping[str, str] = {
            "tenant": tenant_id.lower(),
            "device": device_id.lower(),
            "namespace": self.__namespace,
        }

        if metadata:
            for key, value in metadata.items():
                if key and value:
                    labels[str(key)[:63]] = str(value)[:63]

        stored = self.__secret_manager.store_secret(
            secret_id=secret_id,
            payload=payload,
            labels=dict(labels),
        )
        rotation_due_at = int(time.time()) + self.__rotation_seconds

        return DeviceCredentialRecord(
            credential_reference=stored.reference,
            secret_id=stored.secret_id,
            rotation_due_at=rotation_due_at,
        )

    def __generate_secret_material(self) -> bytes:
        """Generate secret material."""

        return secrets.token_bytes(32)

    def __build_secret_id(self, *, tenant_id: str, device_id: str) -> str:
        """Build the secret ID."""

        tenant_segment = tenant_id.strip().replace(" ", "-").lower()
        device_segment = device_id.strip().replace(" ", "-").lower()
        random_suffix = secrets.token_hex(4)
        
        return f"{self.__namespace}-{tenant_segment}-{device_segment}-{random_suffix}"[:255]


__all__ = [
    "DeviceCredentialRecord",
    "DeviceCredentialService",
]


