## Phase 3 Patch Plan — Reliability, Versioning, Budgets, Caching

### Summary
Introduce reliability features across SSE and Firestore layers: circuit breakers, timeouts/retries, API versioning, and Redis read‑through caching with TTL. Centralize budgets in config, wire DI factories, and add lightweight rate limiting. Target p99 ≤50 ms for data paths, ≤15 ms for cache hits, minimal memory overhead, and observability hooks.

### Patch Plan
| file | op | functions/APIs | tests | perf/mem budget | risk |
|---|---|---|---|---|---|
| `server/services/sse_service/service.py` | update | Add CircuitBreaker wrappers, heartbeat keepalive, client backoff | `tests/unit/sse/test_breaker_and_timeouts.py` | publish→Redis p99 <15ms; keepalive ≤20s; +≤2MB | Aggressive breaker trips reduce availability | DONE |
| `server/services/sse_service/redis_backend.py` | update | Pooled Redis client; op timeouts; retry with jitter/backoff | `tests/unit/sse/test_redis_pool_timeouts.py` | Redis op timeout 10ms; pool ≤64 conns | Pool exhaustion under fan‑out | DONE |
| `server/services/sse_service/factory.py` | update | Inject breaker/budgets from config via DI | `tests/unit/sse/test_factory_injection.py` | factory init <2ms; no global state | Misconfigured DI blocks startup | DONE |
| `server/services/firestore/base.py` | update | Add timeouts, bounded retries, backoff; wrap in breaker | `tests/unit/firestore/test_base_timeouts_retry.py` | read p99 <50ms; write p99 <70ms; retries ≤2 | Hidden latency from retries | DONE |
| `server/services/firestore/users_store.py` | update | Cache user profile by tenant; add v2 method signatures | `tests/unit/firestore/test_users_cache_and_versions.py` | hit p99 <5ms; safe fallback on miss | Version drift between v1/v2 | DONE |
| `server/services/firestore/service_factory.py` | update | Wire cache client, breakers, version registry | `tests/unit/firestore/test_factory_wiring.py` | init <3ms; no circular deps | Wiring errors prevent injection | DONE |
| `server/bas_server.py` | update | Versioning headers (unversioned→v2), deprecation, central error map | `tests/unit/server/test_versioning_and_errors.py` | dispatch overhead <2ms | Client breakage on version switch | DONE |
| `server/auth/middleware.py` | update | Async token‑bucket rate limiter per tenant & API version | `tests/unit/auth/test_rate_limiter.py` | enqueue <1ms; p99 <5ms; mem <5MB | False positives throttle legit traffic | DONE |
| `server/config/config.py` | update | Centralize budgets: timeouts, retries, TTLs; env overrides | `tests/unit/config/test_budgets_config.py` | load <1ms; immutable defaults | Config drift across envs | DONE |
| `server/services/firestore/sessions_store.py` | update | Read‑through Redis for `get_session`; TTL ≤ remaining `expires_at`; explicit invalidations | `tests/unit/firestore/test_sessions_cache.py` | hit p99 <5ms; miss fallback <50ms; mem +≤3MB | Missed invalidation yields stale session | DONE |
| `server/services/firestore/devices_store.py` | update | Cache `get_by_id`; optional first‑page lists and counts with short TTL; precise invalidation | `tests/unit/firestore/test_devices_cache.py` | hit p99 <5ms; list/count p99 <10ms; staleness ≤60s | Invalidation gaps on status/metadata change | DONE |
| `server/services/firestore/audit_store.py` | update | Feature‑flagged short‑TTL cache for recent dashboard view (default off); no cache for other queries | `tests/unit/firestore/test_audit_cache_flag.py` | hit p99 <5ms; TTL ≤20s; default bypass | Stale dashboard view; keep flag off by default | DONE |

### Notes
- Breaker defaults: failure threshold 5 in 30s window; half‑open after 15s.
- Redis TTLs: 30s for telemetry, 60s for profiles; jitter ±10% to avoid thundering herds.
- Versioning: route `v1`/`v2` via router; emit `Sunset` and `Deprecation` headers for `v1`.
  - Update: unversioned `/api/*` now defaults to v2 semantics via headers; `v1` paths are not registered by default. If `v1` endpoints are introduced, they will emit `Deprecation` and `Sunset` headers.
- Error mapping: normalize Firestore/Redis errors to typed API errors with stable codes.
- Observability: export metrics to existing telemetry; add per‑op p95/p99, error rate, breaker state.


### Redis Cache Suitability Updates

| file | verdict | rationale | cache keys/TTL | invalidation |
|---|---|---|---|---|
| `server/services/firestore/sessions_store.py` | Yes (primary or read‑through) | Hot, latency‑sensitive `get_session`; TTL bounded by `expires_at` | `sess:{id}`; TTL=min(remaining_expiry, 30m) | `invalidate_session`, `invalidate_user_sessions`, `cleanup_expired_sessions` |
| `server/services/firestore/devices_store.py` | Yes (targeted) | Frequent by‑ID reads; lists/status/counts benefit with short TTL | by‑ID: `dev:{tenant}_{device}` TTL 30–60s; lists `dev:list:{tenant}:…`; count `dev:count:{tenant}` TTL 30s | Any mutation: `update`, `delete`, `update_last_seen`, `set_status`, metadata |
| `server/services/firestore/audit_store.py` | No (generally) | Write‑heavy, varied queries; staleness outweighs benefit | Optional UI: `audit:recent`, `audit:user:{id}` TTL 10–20s | On new writes affecting cached views (complex; avoid if possible) |

Recommendations
- Sessions: Prefer Redis as source of truth with TTL; persist to Firestore for analytics, or use strict read‑through caching with explicit invalidations and TTL ≤ remaining expiry.
- Devices: Cache by‑ID; optionally cache first pages and counts with short TTLs; ensure precise invalidation on all mutations.
- Audit: Skip caching; if needed for dashboards, cache only first page with very short TTL and accept staleness.


