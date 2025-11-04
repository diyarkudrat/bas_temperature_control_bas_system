from __future__ import annotations

import itertools
from typing import Dict, List

import pytest

from adapters.providers.secret_manager import StoredSecret
from apps.api.services.device_credentials import DeviceCredentialService


class _RecordingSecretManager:
    """Stub secret manager capturing store calls for assertions."""

    def __init__(self, *, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.calls: List[Dict[str, object]] = []

    def store_secret(self, *, secret_id: str, payload: bytes, labels: Dict[str, str]) -> StoredSecret:
        if self.should_fail:
            raise RuntimeError("store-failure")

        self.calls.append({"secret_id": secret_id, "payload": payload, "labels": labels})
        return StoredSecret(reference=f"stub://{secret_id}", secret_id=secret_id, created_at=1700000000.0)


@pytest.fixture(autouse=True)
def _deterministic_entropy(monkeypatch: pytest.MonkeyPatch):
    """Provide deterministic entropy for secret generation."""

    hex_values = itertools.cycle(["abcd1234", "ef567890", "1122aabb"])
    monkeypatch.setattr("apps.api.services.device_credentials.secrets.token_bytes", lambda size: b"X" * size)
    monkeypatch.setattr("apps.api.services.device_credentials.secrets.token_hex", lambda n: next(hex_values))
    monkeypatch.setattr("apps.api.services.device_credentials.time.time", lambda: 1700000000.0)


def test_issue_credentials_includes_metadata_labels():
    manager = _RecordingSecretManager()
    service = DeviceCredentialService(manager, rotation_hours=2, namespace="Provisioning")

    record = service.issue_credentials(
        tenant_id="TenantA",
        device_id="DeviceA",
        metadata={"Env": "Prod", "extra-long-key" * 8: "Value" * 20},
    )

    assert record.credential_reference == f"stub://{record.secret_id}"
    assert record.secret_id.startswith("provisioning-tenanta-devicea-abcd1234")
    assert record.rotation_due_at == 1700000000 + 2 * 3600

    call = manager.calls[-1]
    assert call["payload"] == b"X" * 32
    labels = call["labels"]
    assert labels["tenant"] == "tenanta"
    assert labels["device"] == "devicea"
    assert labels["namespace"] == "provisioning"
    # Ensure metadata keys/values truncated to Secret Manager length constraints.
    truncated_key = next(key for key in labels if key.startswith("extra-long-key"))
    assert len(truncated_key) <= 63
    assert len(labels[truncated_key]) <= 63


def test_issue_credentials_uses_minimum_rotation_window():
    manager = _RecordingSecretManager()
    service = DeviceCredentialService(manager, rotation_hours=0.1, namespace="edge")

    record = service.issue_credentials(tenant_id="tenantA", device_id="deviceA")

    # Rotation hours less than one should clamp to 3600 seconds minimum.
    assert record.rotation_due_at == 1700000000 + 3600


def test_issue_credentials_propagates_secret_manager_errors():
    manager = _RecordingSecretManager(should_fail=True)
    service = DeviceCredentialService(manager, rotation_hours=1, namespace="device")

    with pytest.raises(RuntimeError):
        service.issue_credentials(tenant_id="tenantA", device_id="deviceA")

