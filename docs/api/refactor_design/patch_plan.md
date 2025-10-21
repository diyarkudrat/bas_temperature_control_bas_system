# Patch Plan for Non-Blocking SSE and Auth Token Verification

## Overview
- Implement non-blocking Server-Sent Events (SSE) for real-time telemetry streaming with async I/O, ensuring p99 latency under 50ms and integration with existing telemetry systems.
- Integrate secure auth token verification into SSE endpoints, including role-based access, tenant isolation, and fingerprinting to prevent session hijacking.
- Add modular services, comprehensive testing (unit, integration, stress), performance budgets, and configurations for scalability, error handling, and backward compatibility.

## Summary (78 words)
Implement non-blocking SSE for real-time telemetry streaming with async I/O, integrated auth token verification per DDR. Focus on modular services, error handling, rate limiting, Firestore caching, and tenant isolation. Ensure p99 &lt;50ms latency, horizontal scaling via Redis. Add contract/stress tests. Backward compatible with existing endpoints; budgets prevent cascades.

| file | op | functions/APIs | tests | perf/mem budget | risk |
|------|----|----------------|-------|-----------------|------|
| server/bas_server.py | modify | Add async /api/sse/telemetry route with event streaming | Unit: SSE connect/disconnect; Integration: event emission | p99&lt;50ms, &lt;2MB/stream | Connection leaks (mitigate: timeouts) |
| server/services/sse_service.py | create | SSEService class with async event generator, Redis pub/sub | Unit: event formatting; Load: 100 concurrent streams | &lt;10ms/event, &lt;1MB mem | Pub/sub drift (mitigate: heartbeats) |
| server/auth/middleware.py | modify | Add verify_auth_token async func for SSE handshake | Unit: valid/invalid tokens; Security: injection tests | &lt;5ms verify, &lt;512KB | Token forgery (mitigate: HMAC) |
| server/auth/managers.py | modify | Extend SessionManager with token_verify method | Unit: expiration/roles; Contract: multi-tenant | &lt;3ms, &lt;256KB | Session hijack (mitigate: fingerprints) |
| server/services/firestore/telemetry_store.py | modify | Add async query_recent_stream for SSE feeds | Integration: data consistency; Stress: 1k qps | p99&lt;20ms, &lt;1MB/cache | Staleness (mitigate: TTL=5s) |
| server/config/auth_config.json | modify | Add token_verification configs (keys, ttl) | Config validation tests | N/A | Misconfig (mitigate: schema checks) |
| tests/unit/test_sse_service.py | create | Tests for SSEService event handling | Coverage: 90% | N/A | False positives (mitigate: mocks) |
| tests/integration/test_sse_auth.py | create | End-to-end SSE with auth token flows | Scenarios: connect, stream, disconnect | &lt;100ms e2e | Flaky networks (mitigate: retries) |
| server/services/firestore/service_factory.py | modify | Add async pools for SSE-related services | Unit: pool fallback | &lt;5ms init, &lt;512KB | Pool exhaustion (mitigate: limits) |
| infra/firestore.indexes.yaml | modify | Add SSE telemetry stream indexes | Query perf tests | &lt;10ms query | Cost spike (mitigate: budgets) |
| server/auth/utils.py | modify | Add async token_hash/verify helpers | Unit: hash collisions | &lt;2ms, &lt;128KB | Weak crypto (mitigate: Argon2) |
| tests/contracts/firestore.py | modify | Add SSE stream consistency contracts | Contract: invariance checks | N/A | Violation cascades (mitigate: breakers) |

## Notes
- Use gevent for async in Flask; migrate to Quart if needed for full async. (28 words)
- Enforce D1-D9 from DDR; prioritize tenant isolation in SSE. (12 words)
- All changes backward compatible; deploy with feature flags. (9 words)
