# Database Integration Design — Firestore (v1)

## Table of Contents
- [Overview](#overview)
- [Goals and Non-Goals](#goals-and-non-goals)
- [Current State (inventory)](#current-state-inventory)
- [Options Summary](#options-summary)
- [Architecture](#architecture)
- [Data Model](#data-model)
- [Indexes and TTL Policies](#indexes-and-ttl-policies)
- [Access Patterns & Query Examples](#access-patterns--query-examples)
- [Security and IAM](#security-and-iam)
- [Reliability](#reliability)
- [Cost Model (scenarios)](#cost-model-scenarios)
- [Rollout & Migration](#rollout--migration)
- [Tradeoffs](#tradeoffs)
- [Acceptance Criteria](#acceptance-criteria)
- [Appendix: Implementation Checklist (Flask)](#appendix-implementation-checklist-flask)

## Overview
This design adopts Google Cloud Firestore (Native mode) as the primary database for the BAS portfolio project and designates Cloud SQL for PostgreSQL as a fallback.

What this achieves
- **Cost control**: Target spend well under **$50/month** at showcase scale using Firestore’s pay‑per‑use model and TTLs for automatic pruning.
- **Low operational burden**: Fully managed, serverless database—no servers to patch, scale, or back up manually.
- **Right data model for now**: Firestore fits append‑heavy telemetry, simple auth/sessions, and audit logs with straightforward query patterns.
- **GCP skill building**: Uses IAM, Secret Manager, Cloud Monitoring, and Firestore best practices.

Scope of this design
- Define collections, indexes, and TTL policies for telemetry, users, sessions, audit, and devices.
- Specify secure access patterns and minimal‑cost query shapes for the dashboard and APIs.
- Provide a migration/rollout plan from SQLite with feature flags and rollback.

Outcomes
- A clear, low‑risk path to move from local SQLite to a scalable, cloud‑managed store.
- Predictable costs, better reliability, and a portfolio‑ready architecture that showcases GCP proficiency.

## Goals and Non-Goals
- **Goals**
  - **Affordability**: Stay comfortably under $50/month at showcase scale.
  - **Low Ops**: Managed, serverless database; minimal maintenance.
  - **Mixed Workload**: Append-heavy telemetry; simple auth/session; audit logging.
  - **GCP Learning**: Use IAM, Secret Manager, Monitoring, Firestore.
  - **Multi-tenant Ready**: Include `tenant_id` across data.
- **Non-Goals**
  - Heavy analytics/OLAP (future export to BigQuery/ClickHouse).
  - Complex cross-entity relational joins.

## Current State (inventory)
- SQLite `bas_telemetry.db` contains `telemetry`, `users`, `sessions`, `audit_log`.
- Telemetry writes per request; 7-day purge; auth/session/audit also on SQLite.
- Risks: single-node, no HA/PITR, potential locks, no backups/migrations.

## Options Summary
- **Firestore (Native)**: Serverless, pay-per-use, low ops, GCP-native, easy TTL/IAM. NoSQL modeling; higher vendor lock-in. Fit: High.
- **Cloud SQL (Postgres)**: Standard SQL, portable; more ops and likely >$50/month. Fit: Medium (budget risk).
- **ClickHouse (managed)**: Great analytics; OLTP mismatch and more complexity. Fit: Medium-Low.

Decision: **Firestore primary**, **Cloud SQL Postgres backup**.

## Architecture
```
Clients (Pico/Browser)
        |
        v
 Flask App (Cloud Run or VM)
        |
        v
   Firestore (Native)
   ├─ telemetry (TTL 30–90d)
   ├─ users
   ├─ sessions (short-lived)
   ├─ audit_log (TTL)
   └─ devices
```

**Why this works**
- Serverless scaling, automatic indexes, and TTL policies fit telemetry and audit needs while minimizing operational overhead and cost.

## Data Model
Each collection includes: a quick summary, collection path, common ID convention, example JSON, and key index/TTL notes.

### Collection: telemetry
Overview

| Aspect | Details |
|---|---|
| **Purpose** | Persist device measurements and controller state over time for dashboards and diagnostics |
| **At-a-glance** | Append-only time-series; query by `(tenant_id, device_id)` and time window |
| **Path** | `telemetry` |
| **Document ID** | Auto-ID (server-generated). Alt: `${tenant_id}_${device_id}_${timestamp_ms}` |
| **Index** | Composite `(tenant_id asc, device_id asc, timestamp_ms desc)` |
| **TTL** | Enabled on `timestamp_ms` (retention target: 90 days) |

Example document
```json
{
  "tenant_id": "t_123",
  "device_id": "device_abc",
  "timestamp_ms": 1734398405123,
  "utc_timestamp": "2025-12-17T05:20:05.123Z",
  "temp_tenths": 237,
  "setpoint_tenths": 230,
  "deadband_tenths": 10,
  "cool_active": false,
  "heat_active": true,
  "state": "HEATING",
  "sensor_ok": true
}
```

### Collection: users
Overview

| Aspect | Details |
|---|---|
| **Purpose** | Manage human operators/admins, credentials, roles, and account state |
| **At-a-glance** | Authentication principals; stable `user_id` plus unique `username` |
| **Path** | `users` |
| **Document ID** | `user_id` (UUIDv4) as the document ID |
| **Indexes** | Unique `username`; single-field `user_id` |

Example document
```json
{
  "user_id": "2c7c0f3a-2b07-4d6f-9a61-5c9b7b3f1c9e",
  "username": "operator1",
  "password_hash": "<hashed>",
  "salt": "<salt>",
  "role": "operator",
  "created_at": 1734390000000,
  "last_login": 1734397200000,
  "failed_attempts": 0,
  "locked_until": 0,
  "password_history": ["<old_hash_1>", "<old_hash_2>"]
}
```

### Collection: sessions
Overview

| Aspect | Details |
|---|---|
| **Purpose** | Track active user sessions for authorization and expiry |
| **At-a-glance** | Short-lived session records; filter by `user_id` and `expires_at` |
| **Path** | `sessions` |
| **Document ID** | `session_id` (opaque, random) |
| **Indexes** | `session_id`, `user_id`, `expires_at` |
| **Retention** | TTL or periodic cleanup on `expires_at` |

Example document
```json
{
  "session_id": "sess_5d2e...",
  "user_id": "2c7c0f3a-2b07-4d6f-9a61-5c9b7b3f1c9e",
  "username": "operator1",
  "role": "operator",
  "created_at": 1734397200000,
  "expires_at": 1734400800000,
  "last_access": 1734399000000,
  "fingerprint": "fp_abcd",
  "ip_address": "203.0.113.10",
  "user_agent": "Mozilla/5.0 (...)"
}
```

### Collection: audit_log
Overview

| Aspect | Details |
|---|---|
| **Purpose** | Auditable record of security-relevant events (logins, changes, failures) |
| **At-a-glance** | Append-only audit trail; query by `user_id` and `action` |
| **Path** | `audit_log` |
| **Document ID** | Auto-ID |
| **Indexes** | `timestamp_ms desc`, `action`, `user_id` |
| **TTL** | 180 days |

Example document
```json
{
  "timestamp_ms": 1734398000000,
  "utc_timestamp": "2025-12-17T05:06:40.000Z",
  "user_id": "2c7c0f3a-2b07-4d6f-9a61-5c9b7b3f1c9e",
  "username": "operator1",
  "action": "LOGIN_SUCCESS",
  "ip_address": "203.0.113.10",
  "user_agent": "Mozilla/5.0 (...)",
  "details": {"method": "password"}
}
```

### Collection: devices
Overview

| Aspect | Details |
|---|---|
| **Purpose** | Catalog devices with metadata for organization, lookup, and display |
| **At-a-glance** | Device registry and metadata; join key for telemetry |
| **Path** | `devices` |
| **Document ID** | `${tenant_id}_${device_id}` or auto-ID with fields carrying both IDs |
| **Index** | `(tenant_id, device_id)` |

Example document
```json
{
  "tenant_id": "t_123",
  "device_id": "device_abc",
  "metadata": {
    "location": "Lab-1",
    "model": "Pico-2025",
    "notes": "Installed near intake"
  }
}
```

**Partitioning**: Include `tenant_id` on telemetry/sessions/audit. For very high QPS on a single device, consider sharding by coarse time bucket (likely unnecessary for the showcase).

## Indexes and TTL Policies
Indexes tell Firestore how to efficiently look up and sort documents for your common queries; without them, complex filters or ordered queries may be slow or unsupported. TTL (time-to-live) policies automatically delete old documents based on a timestamp field, keeping storage and costs under control without writing your own cleanup jobs.

Source of truth and deployment
- Maintain a `firestore.indexes.json` file in the repo (e.g., `infra/firestore.indexes.json`).
- Indexes must be deployed before enabling Firestore feature flags; otherwise, some queries will fail until indexes build.
- **Composite index (telemetry)**
```json
{
  "indexes": [
    {
      "collectionGroup": "telemetry",
      "queryScope": "COLLECTION",
      "fields": [
        { "fieldPath": "tenant_id", "order": "ASCENDING" },
        { "fieldPath": "device_id", "order": "ASCENDING" },
        { "fieldPath": "timestamp_ms", "order": "DESCENDING" }
      ]
    }
  ]
}
```

- **TTL enablement (gcloud)**
```bash
gcloud alpha firestore fields ttls update \
  projects/PROJECT_ID/databases/(default)/collectionGroups/telemetry/fields/timestamp_ms \
  --ttl=ON

gcloud alpha firestore fields ttls update \
  projects/PROJECT_ID/databases/(default)/collectionGroups/audit_log/fields/timestamp_ms \
  --ttl=ON
```

**Why**: The composite index powers ordered recent queries; TTLs keep storage and costs in check without app-side jobs.

## Access Patterns & Query Examples
- **Recent N telemetry for a device**
```javascript
const q = db.collection('telemetry')
  .where('tenant_id', '==', tenantId)
  .where('device_id', '==', deviceId)
  .orderBy('timestamp_ms', 'desc')
  .limit(N);
```

- **Time-window query**
```javascript
const since = Date.now() - windowMs;
const q = db.collection('telemetry')
  .where('tenant_id', '==', tenantId)
  .where('device_id', '==', deviceId)
  .where('timestamp_ms', '>=', since)
  .orderBy('timestamp_ms', 'desc')
  .limit(Nmax);
```

- **User lookup**
```javascript
const q = db.collection('users')
  .where('username', '==', username)
  .limit(1);
```

**Guidance**: Keep queries bounded by tenant/device/time; limit N; prefer incremental windows to reduce reads.

Pagination and timezone
- For pagination, use `startAfter(lastDoc)` or `startAfter(lastTimestamp)` with the composite index.
- UI should convert `utc_timestamp` to local time zones (PT/CT/etc.) for display; backend stores only UTC.

## Security and IAM
- **Service Accounts**: one per environment (dev/staging/prod).
- **Roles**: `roles/datastore.user` for app access; `roles/secretmanager.secretAccessor` if using Secret Manager.
- **Secrets**: Store credentials in Secret Manager; fetch at runtime; never commit keys.
- **Data Isolation**: Enforce `tenant_id` checks in Flask middleware; audit privileged actions.

Sessions and authentication
- Prefer opaque, database-backed sessions with Secure, HttpOnly cookies and SameSite=Lax. Avoid JWTs to enable immediate revocation, straightforward rotation on privilege change, and simpler key management in this single-service architecture.
- Bind tenant to the session at login; require a `TENANT_ID_HEADER` on every request and validate it equals the session tenant; validate device ownership before telemetry access.
- Session lifetimes: idle timeout 30 minutes, absolute TTL 12 hours; rotate session ID on privilege elevation and sensitive actions.

Password policy
- Use Argon2id with per-user random salt for `users.password_hash`. Suggested parameters: memory 64–128MB, timeCost 3, parallelism 1. Store algorithm parameters; re-hash legacy or weak hashes on first successful login.

**Why**: Least privilege reduces risk; central secret management prevents leakage; middleware enforcement protects multi-tenant boundaries.

Multi-tenant enforcement
- Every read/write must include a `tenant_id` and be checked in middleware against the caller’s allowed tenants.
- No default tenant. Cross-tenant attempts return 403 and generate an `audit_log` entry.

## Reliability
- **Backups/PITR**: Enable Firestore PITR or scheduled backups as needed.
- **Targets**: RPO < 1 hour; RTO < 1 hour for the showcase.
- **Observability**: Export Firestore metrics/logs to Cloud Monitoring; alert on error rate, latency, and quota anomalies.

## Cost Model (scenarios)
Assume 10 devices, 1 message/10s each (~260k writes/month) and modest dashboard reads.
- **Writes** (~$0.18/100k): ~260k → ~$0.47
- **Reads** (optimized polling): 100k–300k → ~$0.02–$0.30
- **Storage**: tens of MB with 30–90d TTL → cents
- **Other GCP** (Cloud Run, logs, Secret Manager): typically a few dollars

**Conclusion**: Comfortably below the $50/month goal with headroom.

Guardrails and alerts
- Set soft targets: ≤ 50 reads/min for dashboard per active user; ≤ 5 writes/min per device.
- Create alerts if: reads > 1M/day, writes > 500k/day, storage > 1 GB, or error rate > 2% over 5 minutes.

## Rollout & Migration
1. **Provision**: Enable Firestore (Native), Secret Manager, Monitoring; create service account and IAM bindings.
2. **Configure**: TTLs on `telemetry.timestamp_ms` and `audit_log.timestamp_ms`; deploy composite index.
3. **Feature Flags**: `USE_FIRESTORE_TELEMETRY`, `USE_FIRESTORE_AUTH`, `USE_FIRESTORE_AUDIT`.
4. **Migrate Data**:
   - Users: export from SQLite; assign `user_id` (UUID); import into `users`.
   - Sessions: prefer forced re-login at cutover to avoid inconsistencies.
   - Audit: optionally backfill recent 7–30 days.
   - Telemetry: start fresh or backfill last 7 days in batches.
5. **Cutover**: Enable telemetry first, then audit, then auth; verify after each step.
6. **Verification**: Counts and spot checks; validate login/logout; monitor metrics/logs.
7. **Rollback**: Disable flags to fall back to SQLite during the initial window if needed.

**Why**: Phased cutover isolates risk, simplifies rollback, and validates correctness incrementally.

Local development and testing
- Use the Firestore Emulator for local development; configure the app to detect emulator via env var.
- Testing plan:
  - Unit tests for the data access layer (DAL) using the emulator.
  - Integration tests for auth/session/audit flows.
  - E2E tests for feature-flag cutover paths and rollback.

Error handling and retries
- Implement exponential backoff for transient failures and rate limits.
- During initial deploy, handle “index not ready” by retrying after delay.
- Permission errors should return 403, log with context, and emit an audit event.

Data export/analytics (future)
- If long-term trend analysis is needed, consider scheduled export to BigQuery.

## Tradeoffs
- **Pros (Firestore)**: Serverless, low ops, built-in TTL, GCP-native IAM/secrets, cost-effective at small scale.
- **Cons (Firestore)**: NoSQL modeling and vendor lock-in; composite indexes required for some queries.
- **Backup (Cloud SQL)**: Standard SQL and portability, but higher cost/ops; kept for future needs beyond Firestore.

## Acceptance Criteria

## Appendix: Implementation Checklist (Flask)
- Dependencies: `google-cloud-firestore`, `google-auth`, `google-cloud-secret-manager` (if used).
- Config: feature flags (`USE_FIRESTORE_*`), env vars for project/tenant, ADC or Secret Manager for SA.
- Init: create Firestore client on startup; inject into DAL modules (telemetry/users/sessions/audit).
- Index/TTL: apply `firestore.indexes.json`; enable TTLs before enabling flags.
- Middleware: enforce `tenant_id`; audit 403s and privileged actions.
- Sessions: opaque DB-backed cookies (Secure, HttpOnly, SameSite=Lax), idle 30m, absolute 12h, rotate on privilege changes; bind tenant to session; require and validate `TENANT_ID_HEADER`.
- Passwords: Argon2id with per-user random salt; store algorithm params; re-hash legacy on first login.
- Observability: structured logs; monitor read/write counts, latency, error rate, and quotas; enforce PII logging policy.
- Testing: use Firestore Emulator; unit/integration/E2E as outlined; add cutover/rollback tests.
- Firestore collections, composite index, and TTLs (telemetry: 90d; audit: 180d) configured.
- Flask app reads/writes telemetry with `timestamp_ms` and `utc_timestamp`.
- Users and sessions managed in Firestore with `user_id` and proper indexes; sessions re-login on cutover.
- Audit logs ingested and pruned by TTL; cross-tenant access attempts audited.
- IAM least-privilege service account; secrets in Secret Manager; emulator supported locally.
- Dashboard P50 latency ≤ 300ms for last 100 points query; error rate < 2%.
- Projected Firestore spend ≤ $20/month at test traffic; guardrail alerts configured.
- Feature-flag cutover executed with validated rollback.


