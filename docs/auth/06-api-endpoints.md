# API Endpoints

## 🚀 API Endpoints Explained

### Authentication Endpoints

#### `POST /auth/login`
**Purpose**: User login with username/password

**Request**:
```json
{
    "username": "john_operator",
    "password": "SecurePass123!"
}
```

**Success Response**:
```json
{
    "status": "success",
    "expires_in": 1800,
    "user": {
        "username": "john_operator",
        "role": "operator"
    }
}
```
*Also sets an HttpOnly cookie `bas_session_id` with the session token*

- **401 (AUTH_FAILED)**: wrong credentials
- **423 (USER_LOCKED)**: account locked
- **429 (RATE_LIMITED)**: too many attempts (per-IP/user)

#### `POST /auth/logout`
**Purpose**: End user session

**Request**: Session token in cookie or `X-Session-ID` header

**Response**:
```json
{
    "status": "success",
    "message": "Logged out successfully"
}
```

#### `GET /auth/status`
**Purpose**: Check if session is still valid

**Request**: Session token in cookie or `X-Session-ID` header

**Response** (if valid):
```json
{
    "status": "valid",
    "user": {
        "username": "john_operator",
        "role": "operator",
        "login_time": 1700000000
    },
    "expires_in": 1200
}
```

- **400 (NO_SESSION)**: no cookie/header provided
- **401 (SESSION_INVALID)**: expired/invalid session

### Health Endpoints

#### `GET /api/health`
- Returns server health and timestamps.
- Example:
```json
{
  "status": "healthy",
  "timestamp": 1700000000
}
```

#### `GET /api/health/auth`
- Returns provider health.
- Example (fields vary by provider):
```json
{
  "provider": "Auth0Provider",
  "status": "ok"
}
```

### Protected Endpoint Examples

#### `POST /api/set_setpoint` (requires operator+)
Headers (one of):
- `Authorization: Bearer <JWT>` (preferred)
- `X-Session-ID: <session>` or `bas_session_id` cookie

Body:
```json
{
  "setpoint_tenths": 250,
  "deadband_tenths": 10
}
```

#### `GET /api/telemetry?limit=50` (requires read-only+)
Headers (one of):
- `Authorization: Bearer <JWT>`
- `X-Session-ID: <session>` or `bas_session_id` cookie

### Authorization Sensitivity and Overrides

#### Path Sensitivity Rules
- Configured via server configuration (`PATH_SENSITIVITY_RULES`)
- Each rule: `{ "pattern": "^/api/v1/admin/.*", "level": "critical" }` or `["^/api/telemetry/.*", "standard"]`.
- Matching is first-match; non-matching paths default to `critical` (fail-closed).
- Levels:
  - `critical`: requires full metadata role check from provider.
  - `standard`: allows claims-only role check from JWT.

Example:
```json
[
  {"pattern": "^/api/v1/admin/.*", "level": "critical"},
  ["^/api/v1/telemetry/.*", "standard"]
]
```

#### Admin Outage Override (Fail-Closed with Bounded Bypass)
- During metadata outages on `critical` paths, users with `admin` in JWT claims may bypass via claims-only for 300s.
- Every override is audited with event `ADMIN_OUTAGE_OVERRIDE`.
- Timeout is per-user; repeated requests within window are allowed and logged.

#### Troubleshooting
- **401**: missing/expired session cookie or invalid token.
- **403**: authenticated but lacks role or token revoked.
- **429**: rate limits exceeded; check `Retry-After` header.
- **Auth provider issues**: verify `/api/health/auth`; stale JWKS or breaker open → allow a short delay and retry.
- Validate `BAS_PATH_SENS_RULES` JSON and regex. Invalid entries are ignored with warnings.

### Rate Limiting and Revocation (Phase 4)

#### 429: Too Many Requests
- Some endpoints may enforce per-user limits, configured at runtime.
- When exceeded, responses return 429 with header `Retry-After: <seconds>`.
- Limits can be seeded via `USER_RATE_WINDOWS` env or updated via admin API below.

#### Admin: Dynamic Per-User Limits
- `POST /auth/limits` (admin-only)
- Headers: optional `X-Limits-Key: <key>` when `DYNAMIC_LIMIT_API_KEY` is set.
- Body:
```json
{
  "per_user_limits": {
    "/protected": {"window_s": 60, "max_req": 10},
    "*": {"window_s": 60, "max_req": 100}
  }
}
```
- Response: current snapshot `{ "per_user_limits": { ... } }`.

#### Token Revocation
- Tokens may be revoked by `jti`. Revoked tokens are denied with 403 `TOKEN_REVOKED`.
- Revocation TTL defaults to `REVOCATION_TTL_S` (env). Propagation is near-real-time with local cache (≈5s).
