### Summary
Integrate Auth0 for identity with server-controlled authorization and audit. Verify JWTs via Auth0 JWKS with cached keys and dev mocks to survive outages. Roles live in Auth0 user metadata (source-of-truth); mirror to custom claims for fast checks, plus a server revocation list for immediate deny. Authorize using verified tokens and path-sensitive metadata reads with short TTL caches and bust-on-change. Prefer stateless JWT headers; disable cookies by default, enforcing Secure/HttpOnly/SameSite if enabled. Enforce TLS in prod, warn on local HTTP, and forbid cookies without TLS. Log to a separate DB using a strict, redacted schema. Provide an `AuthProvider` and `MockAuth0` for reproducible demos and CI.

### Decisions
ID | statement | rationale | status | invariant? (Y/N)
--- | --- | --- | --- | ---
A1 | Use Auth0 OIDC; verify JWTs via JWKS; cache keys; dev mocks | Standards-based identity; avoids passwords; keeps demos working during outages | proposed | Y
A2 | Configure via env; never embed secrets; provide key rotation scripts | Reduces leakage risk; teaches IAM hygiene; works across dev and prod | proposed | Y
A3 | Store roles in Auth0 metadata; mirror claims; maintain server revocation list | Metadata is source-of-truth; claims are fast; revocation prevents stale privileges | proposed | Y
A4 | Authorize with JWT + metadata; short TTL cache; bust on changes; rate-limit/backoff | Balances freshness/latency; mitigates DoS; optional Redis cache for restart resilience | proposed | Y
A5 | Prefer stateless JWT headers; disable cookies by default; enforce Secure/HttpOnly/SameSite if used | Simplifies prototype; mitigates fixation; preserves web UX when needed | proposed | N
A6 | Enforce TLS in prod; allow local HTTP with warnings; disallow cookies without TLS | Prevents token leakage; reduces dev friction; safe defaults for demos | proposed | Y
A7 | Provide AuthProvider + MockAuth0; fixtures and CI contract tests | Mitigates no emulator; improves reproducibility; isolates vendor specifics | proposed | N
A8 | Log minimal PII to separate DB using strict schema and token redaction | Supports forensics; avoids sensitive data; reduces accidental token logging | proposed | Y

### Phased Implementation Plan
- **Phase 0: Baseline**: Provider interface, env-based config, MockAuth0, health endpoint.
- **Phase 1: Authentication**: JWKS fetch/cache, JWT verification, 401/403 handling, basic metrics.
- **Phase 2: RBAC Source**: Roles in Auth0 metadata; Actions/Rules to mirror roles into custom claims.
- **Phase 3: Authorization**: Middleware with path sensitivity (claims-only vs metadata lookup), fail-closed.
- **Phase 4: Safety Nets**: Server revocation list, per-user rate limits, backoff/circuit breakers.
- **Phase 5: Caching**: In-memory TTL cache; optional Redis for restart resilience; cache-bust on role change.
- **Phase 6: Audit & Observability**: Strict redacted logging schema; minimal PII; latency/error metrics and alerts.
- **Phase 7: Repro & Tests**: Contract tests against dev tenant, mock fixtures, demo scripts for reproducibility.

[Patch Plan excerpt pending]


