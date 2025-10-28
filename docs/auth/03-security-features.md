# Security Features

## 🛡️ Security Features Explained

### JWT Verification (Preferred)
- **Provider-backed**: Verifies `Authorization: Bearer <JWT>` with configured provider
- **Claims-only check**: Allowed for non-critical paths
- **Provider metadata check**: Required for `critical` paths (roles via provider)
- **Admin outage override**: Temporary bypass for admins if provider metadata unavailable (audited)

### Password Security
- **PBKDF2-SHA256**: Industry-standard password hashing
- **Unique salts**: Each password gets its own random salt
- **Strong password policy**: 12+ chars, mixed case, numbers, symbols

### Session Security
- **Fingerprinting**: Sessions tied to browser/device characteristics
- **Automatic expiration**: Sessions expire after 30 minutes
- **Concurrent limits**: Max 3 sessions per user
- **Secure cookies**: HttpOnly, Secure, SameSite flags

### Rate Limiting
- **Request-level**: Token-bucket per tenant/version (configurable; shadow mode supported)
- **Per-user sliding window**: Optional Redis-backed limiter per endpoint
- **Login attempts**: Per-IP and per-user limits; account lockout on repeated failures
- **Retry-After**: 429 responses include `Retry-After` when applicable

### Token Revocation
- **Revocation by jti**: Denies revoked tokens with `403 TOKEN_REVOKED`
- **Local cache**: Small TTL negative/positive cache to reduce Redis calls

### Audit Trail
- **Complete logging**: Every auth event is logged
- **Structured data**: JSON format for easy analysis
- **Performance indexed**: Database indexes for fast queries

### HTTP Headers
- **Security headers**: Applied globally to responses
- **API versioning**: `API-Version` + optional `Deprecation` and `Sunset` for v1
