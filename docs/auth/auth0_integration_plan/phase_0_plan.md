## Phase 0 Patch Plan — Auth0 Integration Baseline

Summary (<=100w): Establish a minimal, testable baseline: provider interface, env-based configuration, MockAuth0 implementation, and a health endpoint. No external Auth0 calls yet. This enables reproducible demos, CI, and sets the contract for later phases (JWKS, RBAC, authorization). Ship fast, with clear tests and safety.

| file | op | functions/APIs | tests | perf/mem budget | risk |
|------|----|-----------------|-------|------------------|------|
| `server/auth/providers/__init__.py` | add | export `AuthProvider`, `MockAuth0Provider` | import test in provider tests | n/a | low: packaging only |
| `server/auth/providers/base.py` | add | `class AuthProvider` (abstract): `verify_token(token:str)->dict`, `get_user_roles(uid:str)->list[str]`, `healthcheck()->dict` | unit: abstract contract test | import-only; <50ms import | low: API drift risk |
| `server/auth/providers/mock_auth0.py` | add | `class MockAuth0Provider(AuthProvider)`; local RS256/JWT verify with generated key pair; static roles; `healthcheck` | unit: verify ok/expired/bad sig/key mismatch; roles lookup | verify <5ms p50; no I/O | low: test token misuse |
| `server/config/config.py` | update | read env: `AUTH_PROVIDER`, `AUTH0_DOMAIN`, `AUTH0_AUDIENCE`; defaults to `mock` | unit: env parsing matrix | import <10ms; no global I/O | medium: config drift |
| `config/auth.example.env` | update | add example vars: `AUTH_PROVIDER=mock`, `AUTH0_DOMAIN=dev-tenant`, `AUTH0_AUDIENCE=bas-api` | n/a | n/a | low: docs stale |
| `server/http/routes.py` | update | new `GET /health/auth` → returns provider `healthcheck()` | http test: 200 + payload schema | p50 <5ms; no alloc spikes | low: route collision |
| `server/bas_server.py` | update | provider wiring: factory by env; inject into app context | unit: factory selects mock | startup unchanged (<50ms) | medium: init order |
| `server/auth/middleware.py` | update | (non-invasive) accept optional provider in ctor; no auth yet | unit: middleware initializes with provider | n/a | low: backward compat |
| `tests/fixtures/auth/mock_tokens.py` | add | helpers to mint/expire RS256 tokens for MockAuth0 | used by provider/http tests | n/a | low |
| `tests/unit/auth/test_mock_auth0_provider.py` | add | success/expiry/bad-aud/bad-iss/key mismatch; roles; healthcheck | asserts and edge cases including key rotation | test runtime <200ms total | low |
| `tests/unit/http/test_health_auth.py` | add | `/health/auth` returns expected schema/status even without network | latency assert p95<20ms | low |
| `server/requirements.txt` | update | add `python-jose[cryptography]` for local JWT RS256 support | import smoke test | +<10MB install; no runtime cost | medium: dep bloat |

Notes (<=50w each):
- MockAuth0 should default to RS256 with generated dev key pair from env/files; never for prod.
- Health payload: `{ provider: name, status: "ok", now_epoch_ms, mode: "mock" }`.
- Keep all new logic behind env `AUTH_PROVIDER=mock` to avoid prod impact.


