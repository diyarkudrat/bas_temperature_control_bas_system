# Testing

## Emulator Setup

```bash
gcloud components install cloud-firestore-emulator
gcloud beta emulators firestore start --host-port=127.0.0.1:8080
export FIRESTORE_EMULATOR_HOST=127.0.0.1:8080
export GOOGLE_CLOUD_PROJECT=your-project-id
```

## Unit Tests (DAL)

- TelemetryRepository: create, recent N, time-window, pagination, tenant enforcement
- UsersRepository: create, get_by_username, unique username guard
- SessionsStore: create/read/delete, expiry/rotation behavior
- AuditLogStore: append and query by user/action

### Example: pytest for TelemetryRepository

Test file: `tests/unit/firestore/test_telemetry_repository.py`

```python
import os
import time
import pytest
from google.cloud import firestore

from server.services.firestore.telemetry_store import TelemetryRepository

@pytest.fixture(scope="module")
def fs_client():
    # Requires emulator running and env vars set in shell
    assert os.getenv("FIRESTORE_EMULATOR_HOST"), "Run Firestore emulator and export FIRESTORE_EMULATOR_HOST"
    assert os.getenv("GOOGLE_CLOUD_PROJECT"), "Export GOOGLE_CLOUD_PROJECT"
    return firestore.Client(project=os.getenv("GOOGLE_CLOUD_PROJECT"))

@pytest.fixture()
def repo(fs_client):
    return TelemetryRepository(fs_client)

@pytest.fixture()
def tenant_and_device():
    return ("t_test", f"dev_{int(time.time())}")

def test_create_and_query_recent(repo, tenant_and_device):
    tenant_id, device_id = tenant_and_device

    # Create a record
    ok = repo.add_telemetry(
        tenant_id,
        device_id,
        {
            "timestamp": int(time.time() * 1000),
            "temp_tenths": 237,
            "setpoint_tenths": 230,
            "deadband_tenths": 10,
            "cool_active": False,
            "heat_active": True,
            "state": "HEATING",
            "sensor_ok": True,
        },
    )
    assert ok is True

    # Query recent
    results = repo.query_recent(tenant_id, device_id, limit=5)
    assert isinstance(results, list)
    assert len(results) >= 1
    first = results[0]

    # Validate important fields present
    assert first["tenant_id"] == tenant_id
    assert first["device_id"] == device_id
    assert isinstance(first["timestamp_ms"], int)
    assert isinstance(first["utc_timestamp"], str)

def test_pagination(repo, tenant_and_device):
    tenant_id, device_id = tenant_and_device

    page1 = repo.query_recent_paginated(tenant_id, device_id, limit=1)
    assert "data" in page1 and "has_more" in page1
    if page1["has_more"]:
        page2 = repo.query_recent_paginated(
            tenant_id, device_id, limit=1, start_after_doc_id=page1["last_doc_id"]
        )
        # Either we get the next page or we are at the end
        assert "data" in page2
```

Notes:
- Use emulator for fast/isolated tests.
- Keep per-test tenants/devices unique to avoid cross-test collisions.

## Integration & E2E

Planned for a future iteration.
- Integration: auth flow, tenant 403 + audit, telemetry ordering and pagination
- E2E: feature-flag cutover/rollback, forced re-login, multi-tenant isolation

## Performance Sanity

- Dashboard last 100 points: P50 ≤ 300ms
- Reads/min ≤ 50 per active dashboard
