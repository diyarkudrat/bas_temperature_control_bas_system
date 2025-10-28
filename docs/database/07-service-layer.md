# Service Layer (DAL)

## Pattern Overview

- Repositories encapsulate Firestore access per collection
- Mixins:
  - `TenantAwareRepository`: enforces `tenant_id`
  - `TimestampedRepository`: adds `timestamp_ms`, `utc_timestamp`, `updated_at`
- Results & Options:
  - `OperationResult`, `PaginatedResult`, `QueryOptions`

Benefits: separation of concerns, consistent error mapping, built-in security and timestamps.

---

## Key Building Blocks

- `adapters/db/firestore/base.py`: Base + mixins + results
- `adapters/db/firestore/models.py`: Dataclasses for entities
- `adapters/db/firestore/service_factory.py`: Client + repo singletons

---

## Adding a New DAL Repository (Example: AlertsRepository)

Goal: Store alert events per tenant and device.

### 1) Model (models.py)

Add a dataclass (example):
```python
@dataclass
class Alert(BaseEntity):
    tenant_id: str
    device_id: str
    timestamp_ms: int
    utc_timestamp: str
    level: str  # e.g., "warning" | "critical"
    message: str
```

### 2) Repository (adapters/db/firestore/alerts_store.py)

```python
from google.cloud import firestore
from .base import TenantAwareRepository, TimestampedRepository, OperationResult
from .models import Alert

class AlertsRepository(TenantAwareRepository, TimestampedRepository):
    def __init__(self, client: firestore.Client):
        super().__init__(client, 'alerts')
        self.required_fields = ['tenant_id', 'device_id', 'level', 'message']

    def create(self, entity: Alert) -> OperationResult[str]:
        self._validate_required_fields(entity.to_dict(), self.required_fields)
        data = self._enforce_tenant_isolation(entity.tenant_id, entity.to_dict())
        data = self._add_timestamps(data)
        doc_ref = self.collection.add(data)
        return OperationResult(success=True, data=doc_ref[1].id)

    def get_by_id(self, entity_id: str) -> OperationResult[Alert]:
        doc = self.collection.document(entity_id).get()
        if not doc.exists:
            return OperationResult(success=False, error='Not found', error_code='NOT_FOUND')
        alert = Alert.from_dict(doc.to_dict())
        alert.id = doc.id
        return OperationResult(success=True, data=alert)

    def update(self, entity_id: str, updates: dict) -> OperationResult[Alert]:
        updates = self._add_timestamps(updates, include_updated=True)
        self.collection.document(entity_id).update(updates)
        return self.get_by_id(entity_id)

    def delete(self, entity_id: str) -> OperationResult[bool]:
        self.collection.document(entity_id).delete()
        return OperationResult(success=True, data=True)
```

### 3) Service Factory (service_factory.py)

Add import and getter:
```python
from .alerts_store import AlertsRepository

class FirestoreServiceFactory:
    # ...
    def get_alerts_service(self) -> AlertsRepository:
        if 'alerts' not in self._services:
            self._services['alerts'] = AlertsRepository(self.client)
        return self._services['alerts']
```

### 4) Wire into Handlers

- In Flask routes or managers, retrieve via the factory:
```python
alerts = service_factory.get_alerts_service()
res = alerts.create(alert_entity)
```

### 5) Indexes & TTL (optional)

- If querying recent alerts by device/time, add a composite index similar to telemetry.
- Consider TTL on `timestamp_ms` if alerts are ephemeral.

### 6) Testing

- Unit test with emulator: CRUD + tenant enforcement + pagination if added.

---

## Legacy Helpers Guidance

- If older code expects dicts/simple params, add thin adapters in the repo (clearly marked deprecated) that call typed methods and return simple shapes.
- Avoid naming collisions: suffix username-based helpers with `_by_username` and keep ID-based as canonical.
