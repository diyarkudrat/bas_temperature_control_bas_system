# Authentication DDR – Improvements

Summary: We propose tightening the BAS authentication surface by isolating prod and dev tenants, shortening access token lifetimes while rotating refresh tokens with reuse detection, and shrinking token payloads. Analysis of the current middleware versus `auth_checks_flow.md` shows OAuth `scope` claims are ignored and the end-to-end verification pipeline is monolithic, so we add unified scope/role parsing and refactor the checks into discrete, reusable stages that mirror the documented flow. Multifactor authentication becomes mandatory for privileged or remote sessions. Service-to-service traffic moves to scoped client-credentials grants with per-service clients, and confidential web apps use authorization code plus PKCE. Authorization decisions share a centralized policy vocabulary but execute adjacent to data access boundaries to limit TOCTOU exposure. Secrets, signing keys, and client credentials move into the managed secrets vault for auditable rotation and zero on-disk sprawl.

| ID | statement | rationale | status | invariant? |
|----|-----------|-----------|--------|------------|
| D1 | Isolate auth tenants by environment | Avoids token leakage across environments and limits blast radius | Proposed | Y |
| D2 | Enforce 5m access tokens with rotating refresh detection | Limits replay window; rotation+reuse detection thwarts stolen refresh tokens | Proposed | Y |
| D3 | Adopt compact JWKS-verified JWT profile with unified scope parsing | Aligns with Auth0 scope semantics and prevents scope-only tokens from bypassing authorization | Proposed | N |
| D4 | Require MFA for privileged and remote interactive logins | Mitigates credential stuffing and phishing escalation | Proposed | Y |
| D5 | Issue per-service client credentials with least-privilege scopes | Prevents horizontal movement and aligns with principle of least privilege | Proposed | Y |
| D6 | Mandate authorization code + PKCE for confidential apps | Defends against code interception and aligns with OIDC best practices | Proposed | N |
| D7 | Centralize policy vocabulary and stage checks via modular pipeline | Matches documented flow, improves readability, and enables per-step extensions | Proposed | Y |
| D8 | Store secrets and signing keys in managed secrets vault | Audited rotation, no raw secrets on disk | Proposed | Y |

Top-5 Risks:
- Refresh reuse detection requires precise telemetry; any blind spots reopen replay risk.
- MFA rollout could push legacy operators to insecure workarounds if UX is poor.
- Central policy vocabulary or scope mapping may lag behind fast-moving services, causing drift.
- Secrets manager outages or latency spikes could block token issuance flows.
- Per-service client lifecycle or pipeline refactor adds operational overhead; stale credentials risk misuse.

