
# Phase 2 Patch Plan: RBAC Source

## Summary
Implement resilient role storage in Auth0 metadata with LRU/Redis caching, idempotent deployment, distributed transactions, strict rate limiting, robust claims parsing, atomic cache busting, and Redis outage fallbacks to minimize staleness and failures. Mirror roles to JWT claims via Actions/Rules. (72 words)

## Patch Plan

| file | op | functions/APIs | tests | perf/mem budget | risk | status |
|------|----|----------------|-------|-----------------|------|--------|
| server/auth/providers/auth0.py | add | set_user_roles(user_id, roles: dict) - Retries with distributed tx support | unit/test_auth0_provider.py: test_set_user_roles_tx | <500ms, <512KB | Partial update on flake | Completed |
| server/auth/providers/auth0.py | add | get_user_roles(user_id) - Cached fetch with version checks for freshness | unit/test_auth0_provider.py: test_get_user_roles_versioned | <300ms, <256KB | Stale data post-revocation | Completed |
| server/auth/providers/mock_auth0.py | add | Mock set/get roles with failure injection and cache simulations | unit/test_mock_auth0_provider.py: test_mock_roles_injected | <100ms, <128KB | Mock/real divergence | Completed |
| scripts/setup_auth.py | modify | Idempotent deploy for Auth0 Action mirroring roles to claims | unit/test_setup_auth.py: test_idempotent_deploy | <2s, <1MB | Corrupted Actions on repeat | Completed |
| server/auth/managers.py | modify | UserManager role ops with distributed transaction wrappers | unit/auth/test_managers.py: test_roles_distributed_tx | <400ms, <384KB | Inconsistent states on net flake | Completed |
| server/auth/services.py | modify | Secure role APIs with strict rate limits and brute-force monitoring | unit/auth/test_services.py: test_role_endpoint_limits | <600ms, <512KB | Brute-force vulnerability | Completed |
| docs/auth/auth0_integration_plan/phase_2.md | add | Doc idempotency, versioning, tx patterns, limits, parsing fallbacks | N/A (doc) | N/A | Prod misconfig | Pending |
| tests/unit/auth/test_auth0_provider.py | add | Tests for mirroring, version staleness, tx rollback, cache races | integration/test_role_claims.py: test_versioned_rollback | <1s, <768KB | Undetected staleness | Pending |
| server/auth/middleware.py | modify | Robust claims parsing with fallbacks and validation safeguards | unit/auth/test_middleware.py: test_parsing_fallbacks | <200ms, <256KB | Crash on malformed claims | Pending |
| server/config/config.py | modify | Env vars for API creds, TTLs, retries, rate limits, version thresholds | unit/test_config.py: test_extended_auth0_env | <100ms, <128KB | Secret exposure | Pending |
| server/services/firestore/lru_cache.py | modify | LRUCache with atomic bust-on-change and read versioning | unit/test_lru_cache.py: test_atomic_bust_versioned | <150ms, <192KB | Race-induced staleness | Pending |
| server/services/sse_service/redis_backend.py | modify | Redis role events with local fallback for outage-resilient busting | unit/test_redis_backend.py: test_redis_fallback_bust | <400ms, <384KB | Amplified staleness on outage | Pending |

## Notes
- Use cache versioning and atomic ops to prevent races and staleness.
- Implement distributed tx patterns for cross-API consistency.
- Add monitoring/alerts for rate limits and deployment idempotency.
- Enhance parsing with safe defaults/fallbacks for Auth0 glitches.
- Phase 2 emphasizes failure isolation and quick recovery.
