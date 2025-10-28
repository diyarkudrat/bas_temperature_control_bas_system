# BAS Backend Engineering Onboarding

Purpose-built documentation for engineers to understand, operate, and extend the BAS backend. This focuses on the Python/Flask server that powers APIs, auth, telemetry, and multi-tenant operations.

---

## 1) Overview

- **Goal**: Reliable backend with modern auth, telemetry, and web APIs.
- **Runtime**: Python 3, Flask. Optional Redis and Firestore (native mode or emulator).
- **Key Services**:
  - HTTP API server (`apps/api/main.py`)
  - Authentication (JWT via provider + session fallback) (`apps/api/http/middleware/auth.py`)
  - Telemetry storage (Firestore repositories) (`adapters/db/firestore/*`)
  - Multi-tenancy middleware (`apps/api/http/middleware/tenant.py`)
  - Rate limiting and token revocation (Redis-backed) (`app_platform/rate_limit/*`, `adapters/cache/redis/*`)

---

## 2) Architecture

High-level flow (per request):

```
Client → Flask App (apps/api/main.py)
  ↳ before_request: attach ServerConfig, rate-limit snapshot, auth provider, metrics
  ↳ Tenant context resolved when Firestore is enabled
Routes (apps/api/http/*_routes.py) → Handlers (apps/api/http/routes.py)
  ↳ Security headers + API versioning applied in after_request
```

Major modules:
- `apps/api/main.py`: App composition root. Wires server config, auth provider, Firestore factory, tenant middleware, error handlers, versioning, and security headers.
- `apps/api/http/*_routes.py`: Blueprints for health, control, telemetry, auth.
- `apps/api/http/routes.py`: Thin request handlers delegating to controller or repository layer.
- `apps/api/http/middleware/auth.py`: `require_auth` decorator (JWT first, session fallback), request and per-user rate limits, token revocation checks, path sensitivity, and audits.
- `apps/api/http/middleware/tenant.py`: Tenant context extraction/caching, isolation decorators.
- `adapters/db/firestore/*`: Repository pattern for telemetry, users, sessions, audit, devices; constructed via `FirestoreServiceFactory`.
- `adapters/providers/*`: Auth providers: Auth0 (JWKS, metadata), MockAuth0 (local RS256), DenyAll.
- `adapters/cache/redis/*`: Revocation service + small in-process revocation cache.
- `app_platform/config/*`: `ServerConfig` with budgets, rate-limit, breaker, cache TTLs.

---

## 3) API & Data Model

Public endpoints (selected):
- Health: `GET /api/health`, `GET /api/health/auth`
- Status/Config: `GET /api/status`, `GET /api/config`
- Control: `POST /api/set_setpoint` (operator+)
- Telemetry: `GET /api/telemetry?device_id=...&limit=N` (read-only+)
- Internal device ingress: `POST /api/sensor_data` (no auth; see deployment notes)
- Auth: `POST /auth/login`, `POST /auth/logout`, `GET /auth/status`, `POST /auth/limits` (admin)

Where defined:
- Blueprints: `apps/api/http/{health_routes.py,control_routes.py,telemetry_routes.py,auth_routes.py}`
- Handlers: `apps/api/http/routes.py`

Primary entities (Firestore repositories under `adapters/db/firestore/`):
- Telemetry (`telemetry_store.py`): tenant_id, device_id, timestamp_ms, temp/deadband/setpoint, actuator states, state, sensor_ok
- Users (`users_store.py`): username, role, credential metadata
- Sessions (`sessions_store.py`): session_id, username/role, fingerprint, expiry, ip/ua, tenant_id
- Audit (`audit_store.py`): event_type, user info, ip/ua, endpoint, details, tenant_id
- Devices (`devices_store.py`): registered devices per tenant

Data shims: HTTP handlers expose simple JSON; Firestore repositories offer typed ops and legacy-compat helpers (e.g., `TelemetryRepository.query_recent`).

---

## 4) Caching & Performance

- **Request rate limiter (in-process token-bucket)**: `_RequestRateLimiter` in `apps/api/http/middleware/auth.py` with env/server-config overrides.
- **Per-user sliding window (Redis)**: `app_platform/rate_limit/sliding_window_limiter.py` used when `per_user_limits` are configured; keyed by user `sub` (unverified) or IP.
- **Revocation cache (process local)**: `LocalRevocationCache` in `adapters/cache/redis/revocation_cache.py` for 5s positive TTL, 1s negative TTL to bound Redis calls.
- **Provider metadata caching**:
  - Auth0 JWKS TTL + breaker (`adapters/providers/auth0.py`)
  - Role metadata with small in-memory cache
- **Tenant context cache**: `TenantMiddleware` caches principal→tenant for 120s with capacity limits.

TTLs and budgets are centralized in `app_platform/config/*` and env; see `ServerConfig`.

---

## 5) Fault Tolerance

- **JWT verification**: Auth0 provider uses a circuit breaker and JWKS cache; failures degrade to clear 4xx/5xx based on context.
- **Admin outage override**: For critical paths, if provider metadata fetch fails, users with admin in JWT claims get a bounded 300s override (audited) with claims-only role checks.
- **Revocation service**: Best-effort Redis; falls back to in-memory store if Redis is unavailable. Local cache prevents thundering herd.
- **Rate limiting**: Shadow mode supported for request-level limiter to observe without blocking.
- **Telemetry writes**: Best-effort; handler swallows Firestore exceptions to avoid impacting control loop responses.

---

## 6) Observability

- **Health endpoints**: `/api/health` (includes Firestore check), `/api/health/auth` (provider state, JWKS age).
- **Metrics**: Lightweight counters in `AuthMetrics` (no external sink by default). Middleware wraps increments in try/except to be non-fatal.
- **Audit**: Auth failures, permission denials, tenant violations routed to Firestore audit when available; otherwise SQLite audit via `application/auth/services`.
- **Headers**: Security and API versioning headers added in `after_request`.

TODO: Wire metrics to Prometheus or logging sink; add structured request logs.

---

## 7) Security & Access

- **Modes**: `auth_config.json` controls `auth_enabled` and `auth_mode` (disabled | shadow | enforced). In enforced mode:
  1) Prefer Bearer JWT via configured provider (`Auth0Provider` or `MockAuth0Provider`).
  2) If allowed by config, fallback to session cookie/header.
- **Path sensitivity**: `ServerConfig.PATH_SENSITIVITY_RULES` (regex→level). `critical` paths require provider metadata role checks; `standard` may use claims-only.
- **Tenant isolation**: `TenantMiddleware` resolves tenant_id (session first, then header) and provides decorators to enforce.
- **Sessions**: SQLite-backed with optional Firestore store; fingerprint-bound, expiring, constrained concurrency.
- **Security headers**: Standard hardening applied to all responses.

PII handling: No PII beyond IP/UA in audit. Username masking recommended in non-audit logs.

---

## 8) Deployment

Dependencies:
- Python 3 + Flask; optional Redis and Firestore (or emulators).
- Local dev: `scripts/setup_emulators.sh` exports `USE_EMULATORS=1`, `EMULATOR_REDIS_URL`, `FIRESTORE_EMULATOR_HOST`, `GOOGLE_CLOUD_PROJECT`.

Run:
- `./scripts/start_bas.sh --server-only`
- Dashboard: `http://localhost:8080/`

Key config sources:
- Env → `app_platform/config/config.py:ServerConfig.from_env()`
- Auth config JSON → `configs/app/auth_config.json`

Note: `/api/sensor_data` is an internal ingestion endpoint; secure by network controls and tenancy in production.

---

## 9) Testing

- Unit tests under `tests/unit/*` and Firestore DAL examples in `docs/database/10-testing.md`.
- Emulator-based testing for Firestore; rate-limit logic can be exercised with Redis locally.
- Auth endpoints and flows: see `docs/auth/10-testing.md`.

Coverage summary (indicative):
- Handlers and middleware are designed for side-effect-free unit testing using dependency injection and request-scoped objects.

---

## 10) Design Decisions (Key Trades)

| Area | Decision | Rationale |
|------|----------|-----------|
| Auth order | JWT first, session fallback | External identity standard + compatibility path |
| Path sensitivity | Fail-closed default to critical | Secure-by-default authorization |
| Revocation | Redis store + local TTL cache | Near-real-time revocation with bounded staleness |
| Firestore | Repository pattern + feature flags | Safe rollout, emulator-first local dev |
| Rate limiting | Request token-bucket + per-user Redis | Global burst control + user fairness |

---

## Change Summary (What was added/rewritten)

| Change | Description |
|--------|-------------|
| New onboarding | This doc consolidates backend architecture, flows, and ops |
| API mapping | Clear mapping from blueprints to handlers and repos |
| Reliability | Documented breakers, overrides, caching, and rate limits |
| Security | Clarified auth modes, path sensitivity, and tenancy |
| Deployment | Centralized config and emulator usage guidance |

---

## Recommendations (Gaps / Unclear Areas)

- Export metrics (Prometheus/OpenMetrics) and add request logging with correlation IDs.
- Add SSE/WebSocket section if used in UI; wire `adapters/messaging/sse/*` to routes.
- Harden `/api/sensor_data` with auth or mutual trust boundary documentation.
- Expand docs on Firestore indexes/TTL activation per `infra/firestore.indexes.json`.
- Add end-to-end tests for critical-path auth + tenancy + telemetry flows.

---

## Next Steps

- Add architecture diagram images (SVG) and sequence diagrams.
- Document rate-limit knobs with examples (`per_user_limits`, shadow mode).
- Provide sample JWT generation for MockAuth0 in local dev.
- Add a short runbook: how to rotate JWKS/credentials, how to revoke tokens.

---

References (selected):
- `apps/api/main.py`, `apps/api/bootstrap.py`
- `apps/api/http/{auth_routes.py,control_routes.py,telemetry_routes.py,health_routes.py,routes.py}`
- `apps/api/http/middleware/{auth.py,tenant.py,security.py,versioning.py}`
- `adapters/db/firestore/{service_factory.py,telemetry_store.py,...}`
- `adapters/providers/{auth0.py,mock_auth0.py,base.py}`
- `adapters/cache/redis/{revocation_service.py,revocation_cache.py}`
- `app_platform/config/{config.py,rate_limit.py,breaker.py,...}`


