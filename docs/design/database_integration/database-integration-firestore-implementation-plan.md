### Firestore Implementation Plan for Flask

---

### 1) Phased Plan

1) **Environment setup**
   - **GCP prerequisites**

     | Item | Details |
     |---|---|
     | Enable APIs | Firestore (Native), Secret Manager, Cloud Monitoring, IAM |
     | Service accounts | `bas-app-dev`, `bas-app-stg`, `bas-app-prod` (per environment) |
     | IAM roles | `roles/datastore.user`; `roles/secretmanager.secretAccessor` (if using secrets) |
     | Secrets | `firestore-project-id`; optional `telemetry/backfill_start_ms` |

   - **Firestore (Native mode)**

     | Item | Details |
     |---|---|
     | Database | Create Firestore database in target region (Native mode) |
     | Index source | Add `infra/firestore.indexes.json` with telemetry composite index |

   - **TTL fields**

     | Field | Retention | Action |
     |---|---|---|
     | `telemetry.timestamp_ms` | 90 days | Enable TTL |
     | `audit_log.timestamp_ms` | 180 days | Enable TTL |

   - **Local development**

     | Item | Details |
     |---|---|
     | Emulator | Install Firestore emulator |
     | Credentials | Use ADC via `gcloud auth application-default login` |
     | Logging | Structured logs to console |
     | Emulator switch | Use when `FIRESTORE_EMULATOR_HOST` is set |

2) **Application changes (Flask)**
  - **Config/flags**: `USE_FIRESTORE_TELEMETRY`, `USE_FIRESTORE_AUTH`, `USE_FIRESTORE_AUDIT`, `GCP_PROJECT_ID`, `FIRESTORE_EMULATOR_HOST`, `TENANT_ID_HEADER`.
  - **Client init**: Single factory (emulator if present; ADC in cloud); inject into DALs at startup.
  - **DAL modules**: TelemetryStore, UsersStore, SessionsStore, AuditLogStore with tenant enforcement, pagination (`startAfter`), UTC timestamps.
  - **Security (passwords)**: Use Argon2id for `users.password_hash` with per-user random salt. Parameters: memory=64–128MB, timeCost=3, parallelism=1. Store `algo_params` alongside hash; re-hash legacy imports on first successful login.
  - **Sessions**: Opaque DB-backed `session_id` (no JWT). Cookies: Secure, HttpOnly, SameSite=Lax. Idle timeout 30m, absolute TTL 12h; rotate on privilege changes; bind to a coarse `fingerprint` (UA/IP). Purge via `expires_at` TTL/sweeper.
  - **Middleware**: Enforce tenant isolation; 403 + audit on violations; normalize UTC. Bind tenant at login to session; require `TENANT_ID_HEADER` on every request; validate header equals session tenant and device ownership (`devices`) before telemetry read/write.
  - **Endpoints**: Gate by flags; telemetry queries use composite index order; auth/session backed by Users/Sessions stores; audit writes via AuditLogStore.
  - **Logging**: Structured; include `tenant_id`, `device_id`, `action`, read/write counts, latency.


3) **Index/TTL deployment**

  | Step | Description |
   |---|---|
   | Index source | Commit `infra/firestore.indexes.json` with `(tenant_id asc, device_id asc, timestamp_ms desc)` |
  | Deploy | Deploy composite indexes before enabling telemetry feature flag |
  | Readiness gate | Block enabling `USE_FIRESTORE_TELEMETRY` until the composite index is READY (verify via `gcloud firestore indexes composite list` or Admin API). If “index not ready,” keep reads on SQLite and retry with backoff. |
   | TTL enablement | Enable TTL on telemetry and audit fields |

4) **Migration approach**

  | Area | Action |
   |---|---|
  | Users | Export from SQLite; ensure UUIDv4 `user_id`; import; verify logins; re-hash weak/legacy hashes to Argon2id on first login |
   | Sessions | Do not migrate; force re-login at cutover |
   | Audit | Optional backfill 7–30 days; tag `source='sqlite_backfill'` |
  | Telemetry | Start fresh or backfill last 7 days in batched writes with backoff (≤ 5 writes/min/device) |

5) **Cutover and rollback**

  | Aspect | Plan |
   |---|---|
   | Flag sequence | telemetry → audit → auth (force re-login on auth cutover) |
   | Verification (each phase) | Functionality, read/write rates, error rate, index health |
  | Rollback | Disable specific flag(s) to return to SQLite; audit the rollback. Telemetry/audit writes during Firestore window are accepted as authoritative (append-only); no rollback for auth (sessions require re-login). |
  | Dual-write/read | Optional short dual-write window for telemetry (write SQLite+Firestore); keep reads on SQLite until index readiness + sample compare is green; no dual-write for auth/audit. |

6) **Observability and cost guardrails**

  | Metric/Limit | Threshold | Action |
   |---|---|---|
   | Reads | > 1M/day | Alert in Cloud Monitoring |
   | Writes | > 500k/day | Alert in Cloud Monitoring |
   | Storage | > 1 GB | Alert in Cloud Monitoring |
  | Error rate | > 2% over 5m | Alert in Cloud Monitoring |
   | Dashboard budget | ≤ 50 reads/min per active dashboard | Enforce via query patterns/caching |
   | Device writes | ≤ 5 writes/min per device | Enforce in app and backfill tooling |
  | API SLOs | P50 ≤ 300ms, P95 ≤ 800ms for telemetry “last 100” query | Alert if breached for 15m |
  | Availability | ≥ 99.5% | Weekly review; incident if < 99.5% |
  | Logging policy | No PII beyond audit IP/UA; mask usernames in non-audit logs; debug sampling ≤10% in prod | Enforced in logger |

---

### 2) Task Breakdown (checklist)

| Theme | Purpose | Acceptance Criteria | Effort | Dependencies | Status |
|---|---|---|---|---|---|
| Infra | Prepare GCP services, IAM, indexes, TTL, emulator | APIs enabled; SAs + roles; emulator runs; indexes deployed; TTLs enabled | M | GCP project access | ✅ **COMPLETED** |
| Backend config/init | Add flags, env, client factory, inject DAL | App runs with emulator/ADC; flags togglable; Firestore ops succeed | M | Infra | ✅ **COMPLETED** |
| TelemetryStore | Telemetry R/W, window and recent queries, pagination, tenant checks | Writes succeed; recent/window queries correct; `startAfter` works; tenant enforced | M | Index, client init | ✅ **COMPLETED** |
| Users/Sessions | Auth/session persistence; re-login at cutover | Login/logout ops; sessions create/read/delete; re-login enforced | M | Client init | ✅ **COMPLETED** |
| AuditLogStore | Append security events; TTL 180d | Events stored; 403s audited; query by `user_id`/`action` | S | Client init, middleware | ✅ **COMPLETED** |
| Security middleware | Enforce multi-tenant isolation | Cross-tenant 403 + audit; happy path OK | M | Auth path | ✅ **COMPLETED** |
| Migration | Users import; optional audit/telemetry backfill | Users present; optional backfills correct; rate limits respected | M | Stores, infra | 🔄 **IN PROGRESS** |
| Testing | Unit (emulator), integration, e2e | Tests green; P50 ≤ 300ms (last 100 pts) | M | Backend | ⏳ **PENDING** |
| Observability | Monitoring dashboards and alerts; logs | Alerts exist; logs include counters; budgets observed; SLOs wired to alerts and dashboards | S | Infra, backend | ⏳ **PENDING** |
| Cutover/rollback | Phased enablement and verification | Phases executed; rollback tested | S | All above | ⏳ **PENDING** |

**Progress Summary:**
- ✅ **Completed (6/10)**: Infrastructure, Backend Config, TelemetryStore, Users/Sessions, AuditLogStore, Security Middleware
- 🔄 **In Progress (1/10)**: Migration
- ⏳ **Pending (3/10)**: Testing, Observability, Cutover/Rollback

---

### 3) File-by-file edit plan (no code)

| File | Changes | Status |
|---|---|---|
| `server/bas_server.py` | Read flags/env; init Firestore client factory (emulator vs ADC); wire DALs; register tenant middleware; gate endpoints. | ⏳ **PENDING** |
| `server/auth/config.py` | Add config keys: flags, project id, emulator host, secret names. | ✅ **COMPLETED** |
| `server/auth/middleware.py` | Tenant enforcement; 403 + AuditLogStore call. | ⏳ **PENDING** |
| `server/auth/models.py` | Ensure `user_id`, `username`, `role`, `expires_at`, `tenant_id` fields. | ⏳ **PENDING** |
| `server/auth/services.py` | Branch to Firestore-backed Users/Sessions on flags; enforce re-login at cutover. | ⏳ **PENDING** |
| `server/auth/managers.py` | Integrate stores for login/logout; structured audit hooks. | ⏳ **PENDING** |
| `server/auth/utils.py` | UUID helpers; UTC timestamp normalization. | ⏳ **PENDING** |
| `server/auth/exceptions.py` | Map permission errors to 403. | ⏳ **PENDING** |
| `server/services/firestore/telemetry_store.py` | TelemetryStore: add, query_recent, query_window, paginate. | ✅ **COMPLETED** |
| `server/services/firestore/audit_store.py` | AuditLogStore: append and query. | ✅ **COMPLETED** |
| `server/services/firestore/users_store.py` | UsersStore: get_by_username/id, create/update. | ✅ **COMPLETED** |
| `server/services/firestore/sessions_store.py` | SessionsStore: create, get, delete, expiry handling. | ✅ **COMPLETED** |
| `server/services/firestore/devices_store.py` | DevicesStore: device management and metadata. | ✅ **COMPLETED** |
| `server/services/firestore/base.py` | Base repository classes and patterns. | ✅ **COMPLETED** |
| `server/services/firestore/models.py` | Domain models with dataclasses and validation. | ✅ **COMPLETED** |
| `server/services/firestore/service_factory.py` | Service factory for dependency injection. | ✅ **COMPLETED** |
| `server/auth/firestore_client.py` | Firestore client factory with emulator support. | ✅ **COMPLETED** |
| `server/auth/tenant_middleware.py` | Multi-tenant middleware with isolation enforcement. | ✅ **COMPLETED** |
| `server/services/logging.py` | Structured logs with `tenant_id`, `device_id`, `action`, counts. | ⏳ **PENDING** |
| `server/config/auth_config.json` | Add flags and project id defaults (non-secret). | ⏳ **PENDING** |
| `config/config.py` | Centralize flags; emulator detection. | ⏳ **PENDING** |
| `infra/firestore.indexes.json` | Composite index source of truth. | ✅ **COMPLETED** |
| `scripts/setup_auth.py`, `scripts/auth_admin.py` | Ensure compatibility with Firestore paths/flags. | ⏳ **PENDING** |
| Tests | Unit: `tests/unit/auth/*`, new `tests/unit/firestore/test_telemetry_store.py`, `.../test_audit_store.py`; Integration: `tests/integration/test_auth_flow_firestore.py`, `.../test_telemetry_queries.py`; E2E: `tests/e2e/test_feature_flag_cutover.py`. | ⏳ **PENDING** |

**Files Completed: 10/22**
**Files Remaining: 12/22**

---

### 4) Commands and snippets

- **Enable services**
```bash
gcloud services enable firestore.googleapis.com secretmanager.googleapis.com monitoring.googleapis.com
```

- **Create service accounts and IAM bindings**
```bash
gcloud iam service-accounts create bas-app-prod --display-name="BAS App Prod"
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:bas-app-prod@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/datastore.user"
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:bas-app-prod@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

- **Secret Manager (example)**
```bash
echo -n "your-gcp-project-id" | gcloud secrets create firestore-project-id --data-file=-
gcloud secrets add-iam-policy-binding firestore-project-id \
  --member="serviceAccount:bas-app-prod@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

- **Initialize Firestore in Native mode**
```bash
gcloud firestore databases create --location=REGION --type=firestore-native
```

- **TTL enablement (fields)**
```bash
gcloud alpha firestore fields ttls update \
  projects/PROJECT_ID/databases/(default)/collectionGroups/telemetry/fields/timestamp_ms \
  --ttl=ON

gcloud alpha firestore fields ttls update \
  projects/PROJECT_ID/databases/(default)/collectionGroups/audit_log/fields/timestamp_ms \
  --ttl=ON
```

- **Index deployment**
```bash
gcloud firestore indexes composite create --project=PROJECT_ID --collection-group=telemetry \
  --field-config field-path=tenant_id,order=ASCENDING \
  --field-config field-path=device_id,order=ASCENDING \
  --field-config field-path=timestamp_ms,order=DESCENDING
# Or from file:
gcloud firestore indexes composite create --quiet --project=PROJECT_ID --index-file=infra/firestore.indexes.json
```

- **Index readiness (example)**
```bash
gcloud firestore indexes composite list --project=PROJECT_ID \
  --filter="collectionGroup=telemetry AND state=READY"
```

- **Firestore Emulator (local)**
```bash
gcloud components install cloud-firestore-emulator
gcloud beta emulators firestore start --host-port=127.0.0.1:8080
# In another shell
export FIRESTORE_EMULATOR_HOST=127.0.0.1:8080
export GOOGLE_CLOUD_PROJECT=your-project-id
```

- **Minimal env vars**
```bash
export USE_FIRESTORE_TELEMETRY=1
export USE_FIRESTORE_AUDIT=1
export USE_FIRESTORE_AUTH=0
export GOOGLE_CLOUD_PROJECT=your-project-id
export FIRESTORE_EMULATOR_HOST=127.0.0.1:8080
export TENANT_ID_HEADER=X-BAS-Tenant
```

- **Secret names (suggested)**
```text
firestore-project-id
auth-admin-username
auth-admin-password-hash
```

---

### 5) Testing Plan

| Level | Coverage |
|---|---|
| Unit (emulator) | TelemetryStore: write, recent N, window, pagination, tenant enforcement; UsersStore: create, get_by_username, unique username guard; SessionsStore: create/read/delete, expiry/rotation behavior; AuditLogStore: append and query by user/action. |
| Integration | Auth flow: login/logout; 403 cross-tenant + audit; Telemetry endpoints: composite index ordering; `startAfter` pagination; Error handling: permission → 403 + audit; “index not ready” → retry/backoff. |
| E2E | Flag cutover and rollback: telemetry → audit → auth; forced re-login; Multi-tenant isolation: dual-tenant tests with no leakage; dual-write/read sanity during telemetry cutover. |
| Performance sanity | Dashboard last 100 points: P50 ≤ 300ms; reads/min ≤ 50 per active dashboard. |

---

### 6) Rollout Plan

| Stage | Steps |
|---|---|
| Staging | Provision Firestore, TTLs, indexes; import sample users; optional backfills; verify index READY; enable telemetry (read still from SQLite) → sample compare → flip reads to Firestore; Enable audit → verify; Enable auth → force re-login → verify. |
| Production | Repeat flag sequence; soak; monitor reads/writes/storage/error rate. |

| Verification (each phase) | Criteria |
|---|---|
| Health | Health endpoints OK |
| Correctness | Queries return expected data; pagination correct |
| Performance | P50 latency within target |
| Alerts | No alert noise beyond thresholds |

| Rollback trigger | Action |
|---|---|
| Error rate > 2% | Disable affected flag(s) and revert |
| Index unusable | Keep reads on SQLite; pause cutover; wait/retry; revert flag if needed |
| Tenant leakage | Revert to SQLite path; audit incident |
| Budget exceed | Disable flag; tune polling; revert as needed |
| SLO breach sustained (15m) | Revert reads to SQLite for telemetry; open incident |

---

### 7) Risks and mitigations

| Risk | Mitigation |
|---|---|
| Index build delays | Pre-deploy indexes; gate flags until ready; retry on “index not ready.” |
| Quota spikes / cost drift | Client caching; strict polling budgets; alerts; cap N. |
| Multi-tenant leakage | Mandatory tenant checks in middleware and DAL; tests; audit 403s. |
| Retry storms | Exponential backoff with jitter; per-endpoint circuit breakers; max retries. |
| Emulator vs prod drift | Run integration on both; staging verification. |
| Session transition issues | Enforce re-login; user banner; audit failures. |
| Password import weaknesses | Enforce Argon2id; re-hash on first login; block unsalted hashes. |
| Rollback divergence | Accept append-only divergence; document; narrow write window. |

---

### 8) Mapping to Acceptance Criteria

| Criterion | How verified |
|---|---|
| GCP-first / Firestore primary | Flags route telemetry/auth/audit to Firestore; infra provisioned; E2E tests pass. |
| TTLs | Telemetry 90d, audit 180d TTLs enabled; UTC timestamps; config verified via `gcloud` and tests. |
| Composite index | `(tenant_id asc, device_id asc, timestamp_ms desc)` defined in `infra/firestore.indexes.json` and deployed; queries succeed. |
| Multi-tenant enforcement | Middleware requires `tenant_id`; 403 + audit on violations; isolation tests pass. |
| Feature flags | Telemetry → audit → auth sequence executed; rollback simulated successfully. |
| Sessions | Re-login enforced at auth cutover; old sessions invalid; tests confirm. |
| Cost guardrails | Monitoring alerts defined; app counters emitted; budgets validated in staging. |
| Local dev | Emulator used; structured logs; Monitoring configured in prod. |
| Error handling | Backoff and index-not-ready retry paths covered by tests; 403 + audit on permission errors. |
| Pagination & UTC | `startAfter` on `timestamp_ms`; backend UTC only; UI handles TZ (not in scope here). |
| Performance | P50 ≤ 300ms for last 100 points in staging verified. |
| Rollout/rollback | Staged plan executed in staging; rollback triggers documented and tested. |


