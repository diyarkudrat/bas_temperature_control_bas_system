# Auth Service Hardening Patch Plan

## Summary

Elevate the service-to-service authentication model, session management, and network posture for the standalone auth service and the main API. Replace symmetric shared tokens, enforce trusted proxy boundaries, harden cookies/CSRF, and align with Auth0 best practices for distributed environments.

## Planned Work

| area | change | owner modules | perf/mem budget | risk |
| --- | --- | --- | --- | --- |
| Service JWT keys | Introduce `ServiceKeySet`, `ReplayCache`, asymmetric signing (RS256/ES256), JTI dedupe, KID rotation | `app_platform/security/service_tokens.py`, `app_platform/security/__init__.py` | Sign/verify ≤2 ms, replay cache ≤1 MB | High |
| API client wiring | Load key pairs from env/KMS, generate per-request JWT with nonce/exp ≤60s, send kid header, enforce allowed algs | `apps/api/clients/auth_service.py` | HTTP overhead negligible | High |
| API ingress sanitization | Apply `ProxyFix` with trusted hops, establish routing-derived tenant/IP context, strip client-supplied tenant headers, sanitize forwarded-for | `apps/api/main.py`, `apps/api/http/middleware/auth.py` | Middleware overhead ≤5 µs | Medium |
| CSRF + cookies | Require CSRF token for login/logout, set `Secure`, `HttpOnly`, `SameSite=Lax/Strict`, rotate session ID on login/privilege change, introduce refresh cookie (sliding window) | `apps/api/http/auth_routes.py`, `apps/auth_service/http/auth_routes.py`, session manager | Cookie issue O(1) | High |
| Rate limiting | Dual-edge rate limits (API coarse IP/tenant, auth service per-user/IP/24), track expensive routes (password reset, signup) | `app_platform/config/auth.py`, `app_platform/rate_limit`, `application/auth/services.py` | Redis/LRU hit ≤1 ms | Medium |
| Auth service verification | Verify service JWTs, enforce nonce/JTI freshness, allow-list service subjects, network ACL enforcement (JWT + optional mTLS), error telemetry | `apps/auth_service/main.py`, `apps/auth_service/http/auth_routes.py` | Verify ≤2 ms | High |
| CORS tightening | Explicit allowed origins, forbid wildcard with credentials, limit headers/methods for auth endpoints | `apps/api/main.py`, CORS config | n/a | Medium |
| Documentation | Document key rotation, CSRF workflow, cookie policy, rate-limit strategy, network ACL expectations with Auth0 integration | `docs/auth/improvements/` | n/a | Low |

## Detailed Code Changes

### 1. Service JWT Keys (`app_platform/security`)
- Replace `sign_service_token`/HMAC helpers with `ServiceKey`, `ServiceKeySet`, `ReplayCache`, `issue_service_jwt`, `verify_service_jwt` using `python-jose` (ES256/RS256).
- Add Redis-backed replay cache integration plus in-process LRU fallback with metrics in `logging_lib/metrics` or new security metrics module.
- Update `app_platform/security/__init__.py` exports; create env-driven loaders for KMS/Secret Manager material (KID, JWKS publishing).

### 2. API Client Wiring (`apps/api/clients/auth_service.py`)
- Load signing keys via new loader, cache `ServiceKeySet` singleton, and issue per-request JWT with `nonce` (random 128-bit), `exp` ≤ 60 s, `nbf`, `jti`.
- Attach `Authorization: Bearer` header plus `X-Service-Token` for legacy fallback (feature flag), include `kid` and enforce allowed algorithms.
- Strip/override tenant/IP headers before outbound call; add structured logging for token issuance failures.

### 3. API Ingress Sanitization (`apps/api/main.py`, `apps/api/http/middleware/auth.py`)
- Configure `ProxyFix` with explicit hop count and trusted proxies list env var; derive canonical client IP/tenant from routing metadata.
- Remove direct use of client-provided `X-Tenant-Id` / `X-Forwarded-For`; populate from verified claims or service config.
- Introduce middleware hook to inject Auth0 tenant claim (`https://bas.system/tenant_id`) into request context.

### 4. CSRF & Cookie Hardening (`apps/api/http/auth_routes.py`, `apps/auth_service/http/auth_routes.py`, `application/auth/sessions.py`)
- Implement double-submit or same-site token for login/logout POSTs (synchronizer token stored in HttpOnly cookie + header).
- Set `Secure`, `HttpOnly`, `SameSite=Lax` for session cookie; add refresh cookie (`bas_refresh_token`) with sliding expiration and rotation on login/privilege escalation.
- Modify session manager to rotate session IDs and invalidate old tokens; persist refresh tokens with hashed storage + binding to device fingerprint.

### 5. Rate Limiting Enhancements (`app_platform/rate_limit`, `application/auth/services.py`, `apps/auth_service/http/auth_routes.py`)
- Compose rate-limit keys: IP, /24 subnet, tenant, username; maintain counters in Redis with Lua-based atomic updates.
- Expose configuration in `AuthConfig` (`login_per_ip`, `login_per_user`, `refresh_per_user`) with sane defaults; propagate to API for coarse-grained gating.
- Emit structured metrics (drops, throttle events) to logging library for observability.

### 6. Auth Service Verification & Network ACL (`apps/auth_service/main.py`, `apps/auth_service/http/auth_routes.py`)
- Integrate `verify_service_jwt` to authenticate API calls, storing claims on request context; enforce `sub` allow-list and `aud`/`iss` checks.
- Use replay cache to reject duplicate `jti`; return 403 with audit logging when invalid.
- Add optional mTLS enforcement (env flag) leveraging Cloud Load Balancer/backend service; log peer cert metadata for audits.
- Replace `_service_token_valid` helper, and update limits endpoint to require JWT + correct scope.

### 7. CORS Tightening (`apps/api/main.py`, CORS config)
- Configure `CORS(app, resources={"/auth/*": {"origins": allowed_origins}})` with explicit origins from env.
- Limit allowed headers/methods (`POST`, `GET`) and enforce `supports_credentials=True` only for trusted origins.
- Ensure preflight caching is set to short TTL (≤ 600 s) and monitored.

### 8. Documentation & Tooling (`docs/auth/improvements/`, runbooks)
- Add operational guide covering key rotation workflow, Redis replay cache maintenance, and incident response for CSRF/credential stuffing.
- Provide sample Terraform/Helm snippets for configuring KMS, Secret Manager, Memorystore, and network firewall rules.
- Update developer onboarding docs to explain new feature flags and local stack requirements (e.g., Dockerized Redis, self-signed certs).

## Decisions on Prior Open Questions

- **Key management**: use Google Cloud KMS for asymmetric key generation with Secret Manager holding the active private key version. Rotation is automated via Cloud Scheduler → Cloud Run job every 30 days, which creates a new key version, updates the Secret alias, and warms JWKS caches.
- **Replay cache backend**: deploy a highly-available Memorystore (Redis) cluster in primary region for nonce/JTI dedupe (2–5 minute TTLs). Retain the in-process LRU as a hot-standby fallback only when Redis is unavailable, emitting metrics so SRE can react.
- **Tenant claims from Auth0**: require Auth0 Organizations and a custom namespaced claim (e.g., `https://bas.system/tenant_id`) plus the built-in `org_id`. The API maps these claims into routing context, enforcing consistency with internal tenant records before populating downstream headers.

## Rollout Strategy

1. Implement key infrastructure + client changes behind feature flags (dual support for legacy shared secret).
2. Deploy API sanitization + CSRF/cookie changes with short-lived staging bake.
3. Enable JWT verification on auth service with monitoring for replay errors.
4. Tighten rate limits and CORS, then drop legacy shared-secret path.
5. Document operational playbooks and rotation processes for SRE handoff.

