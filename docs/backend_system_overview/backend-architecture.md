# Backend Architecture (Developers)

- Entrypoint: `apps/api/main.py` creates the Flask app, loads `ServerConfig`, wires auth provider/metrics, Firestore factory, registers routes and error handlers.
- Request lifecycle: `before_request` attaches `server_config`, dynamic rate-limit snapshot, `auth_provider`, and metrics; optional tenant context. `after_request` applies security + versioning headers.
- Authentication: `apps/api/http/middleware/require_auth` supports modes: disabled, shadow, enforced. Enforced prefers JWT via provider (`Auth0Provider` or `MockAuth0Provider`), then falls back to session cookies.
- Providers: configured via `app_platform/config/config.py` (`auth_provider`, `auth0_domain`, `auth0_audience`). Mock permitted with emulators; otherwise deny-all.
- Sessions & users: Firestore-backed repositories required for auth, sessions, and audit. A local SQLite path exists for transitional local fallback only.
- Rate limiting: per-IP/user auth attempts in `application/auth/services`. Sliding-window request limiting uses Redis (`app_platform/rate_limit/sliding_window_limiter.py`). Metadata limiter protects JWKS/roles.
- Token revocation: Redis-backed revocation store (`adapters/cache/redis/revocation_service.py`) with a small in-process TTL cache used by auth middleware.
- Storage: Firestore repos under `adapters/db/firestore/*` via `FirestoreServiceFactory`. Firestore is required; configure production or start the Firestore emulator.
- SSE: `adapters/messaging/sse` provides an in-process hub (heartbeats) with Redis pub/sub mirroring for fan-out.
- Configuration: `app_platform/config/config.py` loads env + emulator URLs; `configs/app/auth_config.json` controls features like Firestore-backed auth/audit.
- Emulators: `scripts/setup_emulators.sh` exports `USE_EMULATORS=1`, `EMULATOR_REDIS_URL`, `FIRESTORE_EMULATOR_HOST` for local dev.
