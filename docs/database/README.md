# BAS Database (Firestore) - Engineer's Guide

##  Table of Contents

| Section | File | Description |
|---------|------|-------------|
|  **Overview** | [01-overview.md](01-overview.md) | Why Firestore, goals, environments |
|  **Architecture** | [02-architecture.md](02-architecture.md) | Components, client factory, data flow |
|  **Data Model** | [03-data-model.md](03-data-model.md) | Collections, schemas, examples |
|  **Indexes & TTL** | [04-indexes-ttl.md](04-indexes-ttl.md) | Composite indexes and retention policies |
|  **Access Patterns** | [05-access-patterns.md](05-access-patterns.md) | Query shapes, pagination, costs |
|  **Security & Tenancy** | [06-security-tenancy.md](06-security-tenancy.md) | IAM roles, tenant isolation, middleware |
|  **Service Layer (DAL)** | [07-service-layer.md](07-service-layer.md) | Repository pattern, mixins, results |
|  **API Mapping** | [08-api-endpoints.md](08-api-endpoints.md) | How API endpoints use the DB |
|  **Migration & Rollout** | [09-migration-rollout.md](09-migration-rollout.md) | SQLite  Firestore, flags, rollback |
|  **Testing** | [10-testing.md](10-testing.md) | Emulator, unit/integration/E2E |
|  **Monitoring & Cost** | [11-monitoring-cost.md](11-monitoring-cost.md) | SLOs, budgets, alerts, logs |
|  **Simple Explanation** | [12-simple-explanation.md](12-simple-explanation.md) | Non-technical explanation |

---

##  Quick Start

1) Read [01-overview.md](01-overview.md) for the why and what.
2) See [02-architecture.md](02-architecture.md) to understand how it all fits.
3) Use [03-data-model.md](03-data-model.md) when building queries or tests.
4) Before enabling features, confirm [04-indexes-ttl.md](04-indexes-ttl.md) are deployed.
5) For coding against Firestore, follow [07-service-layer.md](07-service-layer.md).

---

##  File Structure

```
docs/database/
├── README.md                    # This index
├── 01-overview.md               # Motivation, goals, environments
├── 02-architecture.md           # Components, client factory, flows
├── 03-data-model.md             # Collections and schemas
├── 04-indexes-ttl.md            # Indexes and retention
├── 05-access-patterns.md        # Query shapes and pagination
├── 06-security-tenancy.md       # IAM and multi-tenant isolation
├── 07-service-layer.md          # DAL repositories and patterns
├── 08-api-endpoints.md          # API ↔ DB mapping
├── 09-migration-rollout.md      # Cutover plan and rollback
├── 10-testing.md                # Emulator + tests
├── 11-monitoring-cost.md        # SLOs, budgets, alerts
└── 12-simple-explanation.md     # Non-technical explanation
```


