# Database Architecture

## 🧱 Components

- Flask app (server) with feature flags
- Firestore client factory (emulator vs ADC)
- DAL (Data Access Layer) repositories (Telemetry, Users, Sessions, Audit, Devices)
- Tenant middleware enforcing isolation
- Monitoring/logging

---

## 🔌 Client Initialization

- Single client via factory; reused across repositories.
- Emulator if `FIRESTORE_EMULATOR_HOST` is set; otherwise ADC in GCP.

```text
App Startup → Service Factory → Firestore Client → Repos (cached)
```

---

## 🏗️ Repository Pattern

- `BaseRepository` for CRUD + error mapping
- Mixins: `TenantAwareRepository`, `TimestampedRepository`
- Standard results: `OperationResult`, `PaginatedResult`, `QueryOptions`

Benefits: separation of concerns, consistent errors/pagination, security by construction.

---

## 🔄 Data Flow (Typical Telemetry Read)

```text
Client → /api/telemetry → Auth + Tenant middleware → TelemetryRepository.query_recent_for_device()
      → Firestore composite index → Results → HTTP JSON
```

---

## 🧭 Flags and Routing

- Telemetry/Auth/Audit paths gated by flags.
- Rollout sequence: telemetry → audit → auth.
- Health checks and readiness gates ensure index readiness before read flip.

---

## 🧳 Environments

- dev: emulator; loose budgets; verbose logs
- stg: real Firestore; index readiness gates; performance sanity
- prod: alerts on read/write/storage/error SLOs

---

## 🔁 Error Handling & Retries

- Centralized mapping (permission → 403; not found → 404-equivalent; others → 500)
- Exponential backoff for transient failures and “index not ready”

Details in [07-service-layer.md](07-service-layer.md) and [11-monitoring-cost.md](11-monitoring-cost.md).
