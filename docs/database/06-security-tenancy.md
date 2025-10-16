# Security & Tenancy

## IAM & Service Accounts

- One service account per environment (dev/stg/prod)
- Minimum role: `roles/datastore.user`
- If using Secret Manager: `roles/secretmanager.secretAccessor`

## Tenant Isolation

- All relevant documents include `tenant_id`
- Middleware enforces `TENANT_ID_HEADER` on requests
- DAL `TenantAwareRepository` ensures `tenant_id` presence/match on writes
- Cross-tenant attempts → 403 and audit `TENANT_VIOLATION`

## Sessions

- Opaque DB-backed sessions (no JWT)
- Cookies: Secure, HttpOnly, SameSite=Lax
- Idle timeout 30m, absolute TTL 12h; rotate on privilege changes
- Session bound to fingerprint (UA/IP); purge via TTL/sweeper

## Logging & Privacy

- Structured logs include `tenant_id`, `device_id`, `action`
- No PII beyond audit IP/UA; mask usernames in non-audit logs
- Debug log sampling ≤10% in prod

## Backoff & Retry

- Use exponential backoff with jitter for transient errors
- Gate feature flags until composite index is READY
