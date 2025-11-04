"""Additional coverage for `DeviceCredentialService`."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from apps.api.services.device_credentials import DeviceCredentialService


class _StubSecretManager:
    """Stub secret manager for testing."""

    def __init__(self):
        self.created = []

    def create_secret(self, name: str, payload: str, *, labels: dict[str, str]):
        self.created.append((name, payload, labels))
        return SimpleNamespace(resource=name)


@pytest.fixture
def secret_manager_stub():
    return _StubSecretManager()


def test_issue_credentials_uses_stub(secret_manager_stub):
    """Test that issue credentials uses the stub."""
    
    service = DeviceCredentialService(secret_manager_stub, rotation_hours=1, namespace="provisioning")

    record = service.issue_credentials(tenant_id="tenant1", device_id="device1", metadata={"region": "us"})

    assert record.secret_id.startswith("provisioning-tenant1-device1")
    assert any(label == "tenant1" for _, _, labels in secret_manager_stub.created for label in labels.values())
    assert record.rotation_due_at >= int(time.time()) + 3600 - 5


def test_rotation_window_applies_default(secret_manager_stub):
    service = DeviceCredentialService(secret_manager_stub, rotation_hours=None, namespace="default")

    record = service.issue_credentials(tenant_id="tenant2", device_id="device2", metadata={})

    assert record.rotation_due_at - record.rotation_requested_at <= 90 * 24 * 3600

