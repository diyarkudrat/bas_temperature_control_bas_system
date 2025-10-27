BAS Project — File Structure Migration Plan

Goals
- Modular hexagonal layout (apps, application, domains, adapters, platform)
- 12‑factor friendly: explicit config, stateless processes, logs
- Easier testing (unit vs integration vs contracts) and future microservice split
- Preserve behavior during migration with shims and phased PRs

Target structure (end state)
```
.
├── apps/
│  ├── api/
│  │  ├── main.py                 # Flask app factory / entrypoint
│  │  ├── bootstrap.py            # DI: wire configs, providers, repos, middleware
│  │  └── http/
│  │     ├── routes/              # route handlers (thin)
│  │     ├── middleware/          # auth/tenant/security adapters
│  │     └── versioning.py
│  ├── worker/
│  │  └── main.py                 # background jobs/events (future)
│  └── cli/
│     └── manage.py               # admin/ops CLI
├── application/                  # use-case orchestration
│  └── auth/
│     ├── commands.py             # LoginUser, Logout, RotateSession
│     └── queries.py              # GetSessionStatus, AuthorizeRoles
├── domains/                      # pure business logic (no IO)
│  ├── auth/
│  │  ├── models.py               # User, Session (domain)
│  │  ├── services.py             # PasswordPolicy, RoleService
│  │  └── policies.py             # invariants and rules
│  ├── telemetry/
│  └── devices/
├── adapters/                     # ports/adapters implementations (IO)
│  ├── db/
│  │  ├── firestore/              # repositories + budgets
│  │  └── sqlite/                 # local sqlite tables/helpers
│  ├── cache/
│  │  └── redis/                  # revocation store, rate windows
│  ├── messaging/
│  │  └── sse/                    # in-process hub + redis mirror
│  └── providers/
│     ├── auth0/
│     ├── mock_auth0/
│     └── deny_all/
├── platform/                     # cross-cutting platform building blocks
│  ├── config/                    # ServerConfig, budgets, loaders
│  ├── errors/                    # API error mapping/handlers
│  ├── observability/             # metrics, logging, tracing hooks
│  ├── rate_limit/                # token buckets, sliding windows
│  ├── security/                  # headers, CSP
│  └── utils/                     # time, backoff, normalization
├── configs/
│  ├── app/                       # auth_config.json etc.
│  └── templates/                 # secrets/env templates
├── tests/
│  ├── unit/
│  ├── integration/
│  ├── contracts/
│  ├── fixtures/
│  └── plugins/
├── deploy/
│  ├── docker/
│  ├── k8s/
│  ├── terraform/
│  └── .github/workflows/
├── scripts/
├── docs/
└── tools/
```

Phased migration (safe, incremental)

Phase 0 — Prep and scaffolding (PR#1)
1. Create directories and package inits (keep existing code untouched):
   - apps/api/{http/routes,http/middleware}
   - domains/auth, application/auth
   - adapters/{db/firestore,db/sqlite,cache/redis,messaging/sse,providers/{auth0,mock_auth0,deny_all}}
   - platform/{config,errors,observability,rate_limit,security,utils}
   - configs/{app,templates}
   - Ensure each Python directory has an __init__.py
2. Add pyproject.toml (or keep setup.cfg) and make repository importable via editable install.
3. CI: ensure existing tests still run (no moves yet).

Phase 1 — App boundary and HTTP (PR#2)
1. Move `server/bas_server.py` → `apps/api/main.py`.
   - Keep same Flask app creation; adjust relative imports to new packages.
   - Option A (recommended): leave a thin runner at server/bas_server.py that imports and runs apps.api.main for local scripts during transition.
2. Move `server/http/` → `apps/api/http/` (preserve `routes.py`, `versioning.py`).
3. Update entrypoint scripts and docs to start `apps.api.main`.

Phase 2 — Platform config & errors (PR#3)
1. Move `server/config/*.py` → `platform/config/` (including rate_limit, breaker, budgets).
2. Move runtime JSON files:
   - `server/config/auth_config.json` → `configs/app/auth_config.json`.
   - Keep `.env`/templates under `configs/templates/` (move existing templates).
3. Move `server/errors.py` → `platform/errors/api.py`. Update import in app bootstrap.

Phase 3 — Auth adapters vs domain (PR#4)
1. Providers (IO): move `server/auth/providers/*` → `adapters/providers/{auth0,mock_auth0,deny_all}/` and keep package `adapters/providers/__init__.py` that exports the factory functions and interfaces.
2. Revocations & rate limiting:
   - Move `server/auth/revocation_service.py` → `adapters/cache/redis/revocation_service.py`.
   - Move `server/auth/revocation_cache.py` → `adapters/cache/redis/revocation_cache.py` (or `adapters/cache/local/` if preferred).
   - Move `server/auth/metadata_limiter.py` and `server/auth/sliding_window_limiter.py` → `platform/rate_limit/`.
3. Metrics: move `server/auth/metrics.py` → `platform/observability/metrics.py` (preserve `AuthMetrics` alias).
4. Circuit breaker: keep shared breakers in `platform/utils/` or leave provider-specific breakers alongside adapters.

Phase 4 — Auth domain and application (PR#5)
1. Domain models/services:
   - Move `server/auth/models.py` → `domains/auth/models.py`.
   - Extract business-only services from `server/auth/managers.py` & `role_service.py` into `domains/auth/services.py`.
2. Application orchestration:
   - Create `application/auth/commands.py` with `LoginUser`, `Logout`, `RotateSession` orchestrating adapters and domain.
   - Create `application/auth/queries.py` with `GetSessionStatus`, `AuthorizeRoles`.
3. Keep data-access and provider calls in adapters; keep policy/permission checks in domains/services.

Phase 5 — Datastores and SSE (PR#6)
1. Firestore repositories: move `server/services/firestore/*` → `adapters/db/firestore/*` (preserve public API names).
2. SQLite helpers: extract sqlite parts from `server/auth/managers.py` into `adapters/db/sqlite/{users.py,sessions.py}` (wrappers used by application layer during transition).
3. SSE service: move `server/services/sse_service/*` → `adapters/messaging/sse/*`.

Phase 6 — HTTP middleware adapters (PR#7)
1. Move `server/auth/middleware.py` → `apps/api/http/middleware/auth.py` (thin adapter calling application layer; maintain same Flask decorator names for now).
2. Move `server/auth/tenant_middleware.py` → `apps/api/http/middleware/tenant.py`.
3. Keep `add_security_headers` under `apps/api/http/middleware/security.py` or `platform/security/headers.py` and import into app.

Phase 7 — Wiring/bootstrap (PR#8)
1. Create `apps/api/bootstrap.py` that wires:
   - `platform/config.ServerConfig`
   - adapters: providers, firestore factory, redis clients
   - application services and middleware
2. Update `apps/api/main.py` to use bootstrap, attach `request.server_config`, `request.auth_provider`, metrics, etc.

Phase 8 — Tests re-organization (PR#9)
1. Mirror new layout under `tests/`:
   - unit/domains/*, unit/application/*, unit/platform/*
   - integration/adapters/* (with emulators)
   - contracts/providers/*, contracts/db/* (behavioral contracts)
2. Keep existing tests passing by introducing temporary import shims (next phase) before moving tests.

Phase 9 — Temporary import shims (PR#10)
1. Create shim modules to avoid big-bang renames. Examples:
   - `server/auth/providers/__init__.py` re-export from `adapters.providers.*`.
   - `server/auth/metrics.py` re-export `platform.observability.metrics`.
   - `server/config/*` re-export from `platform.config.*`.
2. Remove shims after all import paths are updated and tests are green (Phase 12).

Phase 10 — Bulk import rewrites (PR#11)
1. Perform module path rewrites (scripted). Examples patterns to apply repo-wide:
   - `server.http` → `apps.api.http`
   - `server.config` → `platform.config`
   - `server.errors` → `platform.errors`
   - `server.auth.providers` → `adapters.providers`
   - `server.services.firestore` → `adapters.db.firestore`
   - `server.services.sse_service` → `adapters.messaging.sse`
   - `server.auth.metadata_limiter|sliding_window_limiter` → `platform.rate_limit.*`
   - `server.auth.metrics` → `platform.observability.metrics`
2. Re-run tests and linters; keep shims to catch any missed imports.

Phase 11 — Configs, scripts, and deploy (PR#12)
1. Update scripts to use `apps/api/main.py` entrypoint.
2. Move Dockerfiles/workflows under `deploy/`:
   - `deploy/docker/api.Dockerfile`, `deploy/.github/workflows/ci.yml` (lint, unit, integration with emulators).
3. Update docs references to new paths; ensure `configs/app/auth_config.json` is the runtime source of truth.

Phase 12 — Remove shims and cleanup (PR#13)
1. Delete temporary shim modules.
2. Final pass of import tidy; enforce `from X import Y` matching the new layers.
3. Freeze a tag prior to shim removal for rollback.

Concrete move map (non-exhaustive)
- server/bas_server.py → apps/api/main.py
- server/http/* → apps/api/http/*
- server/errors.py → platform/errors/api.py
- server/config/*.py → platform/config/*.py
- server/config/auth_config.json → configs/app/auth_config.json
- server/auth/models.py → domains/auth/models.py
- server/auth/role_service.py → domains/auth/services.py (authorization logic)
- server/auth/managers.py →
  - domains/auth/services.py (domain logic)
  - adapters/db/sqlite/{users.py,sessions.py} (sqlite access)
- server/auth/middleware.py → apps/api/http/middleware/auth.py
- server/auth/tenant_middleware.py → apps/api/http/middleware/tenant.py
- server/auth/metrics.py → platform/observability/metrics.py
- server/auth/metadata_limiter.py → platform/rate_limit/metadata_limiter.py
- server/auth/sliding_window_limiter.py → platform/rate_limit/sliding_window_limiter.py
- server/auth/revocation_service.py → adapters/cache/redis/revocation_service.py
- server/auth/revocation_cache.py → adapters/cache/redis/revocation_cache.py
- server/auth/providers/* → adapters/providers/*
- server/services/firestore/* → adapters/db/firestore/*
- server/services/sse_service/* → adapters/messaging/sse/*

Shim examples (temporary)
- server/auth/providers/__init__.py:
  - `from adapters.providers import *  # noqa`
- server/auth/metrics.py:
  - `from platform.observability.metrics import *  # noqa`
- server/config/__init__.py:
  - re-export `platform.config.*`

Verification checklist per phase
- CI is green (lint + unit) before/after each PR
- App boots and /api/health OK
- JWT auth endpoints and session auth tested via existing unit/integration tests
- Rate-limits and revocation code paths exercised
- No circular imports across layers (apps → application → domains/adapters/platform)

Rollback plan
- Tag repo before each phase (vX.Y-migrate-stepN)
- Shims allow quick revert of import rewrites
- Keep a temporary branch with original tree until Phase 12 completed

Suggested command snippets (adapt as needed)
```
# 0) create directories
mkdir -p apps/api/http/{routes,middleware} apps/worker apps/cli \
  application/auth domains/auth \
  adapters/{db/firestore,db/sqlite,cache/redis,messaging/sse,providers/{auth0,mock_auth0,deny_all}} \
  platform/{config,errors,observability,rate_limit,security,utils} \
  configs/{app,templates}

# 1) move top-level server app and http
git mv server/bas_server.py apps/api/main.py
git mv server/http apps/api/http

# 2) move configs and errors
git mv server/config/*.py platform/config/
git mv server/config/auth_config.json configs/app/
git mv server/errors.py platform/errors/api.py

# 3) move auth providers and platform pieces
git mv server/auth/providers adapters/providers
git mv server/auth/metrics.py platform/observability/metrics.py
git mv server/auth/metadata_limiter.py platform/rate_limit/
git mv server/auth/sliding_window_limiter.py platform/rate_limit/
git mv server/auth/revocation_service.py adapters/cache/redis/
git mv server/auth/revocation_cache.py adapters/cache/redis/

# 4) firestore + sse
git mv server/services/firestore adapters/db/
git mv server/services/sse_service adapters/messaging/sse

# 5) domain/application auth
git mv server/auth/models.py domains/auth/models.py
git mv server/auth/role_service.py domains/auth/services.py
git mv server/auth/middleware.py apps/api/http/middleware/auth.py
git mv server/auth/tenant_middleware.py apps/api/http/middleware/tenant.py
```

Notes & trade-offs
- Shims minimize blast radius while imports are rewritten.
- Splitting domain/application/adapters clarifies responsibilities and enables future service extraction.
- Platform centralizes config, errors, observability, and rate-limits for consistency.


