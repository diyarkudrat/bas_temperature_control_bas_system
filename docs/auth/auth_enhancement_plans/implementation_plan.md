# Implementation Plan for BAS Authentication System Upgrade

## Overview
This Patch Plan outlines the incremental implementation of the approved DDR for the BAS authentication upgrade.
    - Phase 1 -> builds foundational setup and core auth primitives.
    - Phase 2 -> layers RBAC and resilience patterns.
    - Phase 3 -> adds advanced security and observability.

## Patch Plan

| File | Op | Functions/APIs | Tests | Perf/Mem Budget | Risk |
|------|----|----------------|-------|-----------------|------|
| server/auth/config.py | Modify | load_identity_config(), adaptive_ttl_config() | unit: test_config_load, test_ttl_adjust | N/A | Config parse errors on env changes |
| server/auth/services.py | Add | init_firebase_auth() | unit: test_init_auth; integration: mock_sdk_init | <10ms init; <1MB mem | SDK init failure in cold starts |
| server/auth/models.py | Add | JWTModel, RefreshToken | unit: test_jwt_encode_decode, test_ttl_adaptive; contract: schema_validation | <10ms encode; negligible mem | TTL miscalc in high-latency nets |
| server/auth/services.py | Modify | verify_token() | unit: test_verify_jwt; integration: mock_sdk_calls | <50ms validation; <1MB mem | Adaptive TTL issues in verification |
| services/firestore/rbac.py | Add | enforce_rbac_rules(), index_setup() | unit: test_rule_enforce, test_query_opt; e2e: role_deny_access | <20ms query; <5MB index mem | Rule misconfig exposes data |
| server/auth/middleware.py | Modify | auth_middleware(), rbac_check() | unit: test_mw_auth, test_rbac_fail; integration: api_endpoint_sec | <5ms mw overhead | Bypass via malformed headers |
| server/auth/services.py + middleware.py (Phase 1 Checkpoint) | Add/Test | N/A (validation: integrate core auth flow) | integration: full_phase1_e2e (login + RBAC); smoke: manual API calls | <80ms end-to-end | Integration gaps in early flow |
| server/auth/services.py | Add | redis_cache_token(), cache_validate() | unit: test_cache_set_get, test_poison_mitigate; perf: load_1k_tokens | <2ms cache hit; <10MB Redis | Cache poisoning without sig checks |
| server/auth/utils.py | Add | circuit_breaker(), retry_sdk_call() | unit: test_cb_open_close, test_retry_exp; chaos: sim_outage | <100ms retry total | Cascade fails without breaker |
| server/auth/services.py + utils.py (Phase 2 Checkpoint) | Add/Test | N/A (validation: resilience under load) | perf: stress_test_caching_breakers; integration: outage_simulation | <100ms under 10% failure rate | Resilience not covering all paths |
| server/auth/services.py | Modify | mfa_enforce_role(), iot_exempt_auth() | unit: test_mfa_mandate, test_sa_bypass; e2e: device_login | <30ms mfa check | Exemption gap for compromised SA |
| server/auth/services.py | Add | mirror_auth_event(), ttl_spike_guard() | unit: test_event_mirror, test_guard_drop; integration: burst_1k_events | <50ms write; cap 100/s | Log loss in spikes despite guards |
| server/config/auth_config.json + server/auth/middleware.py | Modify | Add HSTS headers, HTTPS enforce; https_redirect(), hsts_header() | unit: test_redirect, test_header_set; integration: curl_https | <1ms header add | Deploy without HTTPS exposes tokens |
| server/auth/services.py + middleware.py + config (Phase 3 Checkpoint) | Add/Test | N/A (validation: full system security/observability) | e2e: complete_auth_flow_with_mfa_audit; security_scan: basic vuln check | <150ms full flow | Overlooked trade-offs in exemptions/guards |
| requirements.txt | Add | firebase-admin==6.5.0, redis==5.0.1 | N/A | N/A | Version conflicts on upgrade |

## Notes
- **Phase 1 (rows 1-7)**: Core setup and auth basics. Start with config to learn env-driven init, then build/test primitives sequentially. Checkpoint (row 7) reinforces request flow principles via e2e tests—debug here to understand layers.
- **Phase 2 (rows 8-10)**: RBAC integration and resilience. Assumes Phase 1 solid; add caching/breakers to see perf gains firsthand. Checkpoint (row 10) teaches fault tolerance via chaos testing, building intuition for distributed systems.
- **Phase 3 (rows 11-15)**: Advanced features. Layer MFA/auditing on resilient base; merge transport security for holistic view of endpoints. Final checkpoint (row 14) validates DDR trade-offs (e.g., IoT usability vs. security). 
- **Learning Focus**: Each row's tests scaffold skills—incremental commits let you iterate on failures, mirroring real projects. Post-phase: Review telemetry.py metrics to reflect on budgets/risks. After all PRs: Run full pytest, deploy staging, audit for regressions.
- Budgets target p99; adjust based on personal hardware. Total rows increased slightly for clarity, but stays actionable under 12 core changes + checkpoints.
