import time

import pytest

from adapters.providers.secret_manager import SecretManagerAdapter
from apps.api.services.device_credentials import DeviceCredentialService


@pytest.mark.unit
def test_issue_credentials_with_fallback_secret_manager():
    adapter = SecretManagerAdapter(project_id=None, fallback_prefix="test")
    service = DeviceCredentialService(adapter, rotation_hours=1, namespace="provisioning")

    record = service.issue_credentials(tenant_id="tenantA", device_id="deviceA", metadata={"foo": "bar"})

    assert record.credential_reference.startswith("test://")
    assert record.secret_id.startswith("provisioning-tenantA-deviceA")
    assert record.rotation_due_at >= int(time.time()) + 3600 - 5

