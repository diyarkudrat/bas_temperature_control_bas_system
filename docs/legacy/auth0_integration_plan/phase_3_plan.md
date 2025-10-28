# Phase 3 Implementation Plan: Authorization (Revised)

### Summary
Implement path-sensitive authorization with enhanced mitigations for webhook reliability, evasion, abuse, spikes, bias, and false positives. Include retries, adaptive limits, audits, bounds, dynamic sampling, and tuning for robust scalability (&lt;100 words).

### Patch Plan

| file | op | functions/APIs | tests | perf/mem budget | risk |
|------|----|----------------|-------|-----------------|------|
| server/auth/middleware.py | modify | Enhance require_auth with path_classify(), claims_only_check(), full_metadata_check(); add admin_outage_override() with audit and timeout | Unit/integration tests for classification, overrides/audits, fail-closed; fuzz regex | &lt;5ms latency bound, &lt;2KB mem; &lt;1% error rate | Misclassification/regex errors or override abuse; mitigated by fuzz tests, audits, timeouts |
| server/auth/providers/auth0.py | modify | Extend get_user_roles() with cached_metadata_lookup(), force_refresh, cache_bust_on_event() incl. retries/heartbeats | Tests for cache hit/miss/staleness, busting reliability, revocation with partitions | &lt;50ms fetch, 512KB cache; TTL=60s critical | Staleness from webhook failures; mitigated by retries, heartbeats, fallback TTLs |
| server/config/cache_ttls.py | modify | Define tiered TTLs: AUTH_METADATA_TTL_CRITICAL=60, STANDARD=300; env overrides | Config tests, dynamic TTL switching | n/a | Delayed propagation; mitigated by tiered TTLs |
| server/auth/utils.py | add | Implement rate_limit_metadata_fetch() with per-user/global/adaptive limits (100/min) and backoff | Tests for limits/adaptivity, DoS/evasion scenarios | &lt;1% CPU, &lt;100KB mem; sustain 1k qps | Evasion via rotation; mitigated by adaptive global caps |
| server/auth/managers.py | modify | Update get_effective_user_roles() to prefer metadata, bounded fallback to claims with circuit breakers | Tests for preference, bounded fallbacks, bypass; outage simulations | &lt;2ms exec bound, low mem; &lt;0.1% fallback | Latency spikes or breaker false positives; mitigated by bounds, tuning/tests |
| server/config/config.py | modify | Add PATH_SENSITIVITY_RULES with regex validation func and audit logging | Tests for rule matching/validation, default closed; regex fuzzing | &lt;1KB mem | Regex mismatches; mitigated by validation and logging |
| tests/unit/auth/test_middleware.py | add | Suites for path sensitivity, fail-closed, overrides/audits, hybrid flows | n/a | n/a | Coverage gaps; expanded to include hybrids/audits |
| server/auth/role_service.py | modify | Enhance is_authorized_for_path() with strict hierarchy checks and debug mode | Unit tests for hierarchies, edges; property-based testing | &lt;1ms check, low mem | Logic flaws in inheritance; mitigated by property tests |
| docs/auth/06-api-endpoints.md | update | Document sensitivity rules, overrides/audits, troubleshooting | Manual review | n/a | Doc drift; updated with examples |
| server/config/rate_limit.py | modify | Add METADATA_FETCH_RATE_LIMIT with global/per-user/adaptive defaults | Validation tests, load/evasion simulations | n/a | Misconfigs/evasion; tested under load |
| tests/integration/auth/test_auth0.py | add | E2E tests for auth flows, outages, revocations, compatibility, breaker tuning | n/a | n/a | Flakiness; use mocks for stability |
| server/auth/metrics.py | modify | Add dynamic sampled counters (1-10%) for success/fetches/fails; latency histograms | Tests for sampling adjustment, no overload/bias; stress tests | &lt;0.1% overhead even at peaks | Sampling bias missing rares; mitigated by dynamic rates |

### Notes
- Fail-closed with admin overrides: Allow configurable admin bypass during outages with audits and auto-timeouts to prevent abuse.
- Cache-busting: Integrate event hooks with retries, heartbeats, and fallback polling for reliability.
- Backward compatibility: Add hybrid flow tests ensuring session/JWT interop; monitor for silent failures.
- Latency safeguards: Add circuit breakers with tuning and tests to avoid false positives; bound fallback times (&lt;50 words per note).
