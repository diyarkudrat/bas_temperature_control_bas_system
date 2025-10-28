# Configuration

## 🔧 Configuration Explained

### Authentication Modes
```python
# In config/auth_config.json
{
    "auth_enabled": true,                    # Master switch
    "auth_mode": "user_password",            # "disabled" | "shadow" | "user_password"
    "session_timeout": 1800,                 # 30 minutes
    "max_concurrent_sessions": 3,            # Per user limit
    "max_login_attempts": 5,                 # Before lockout
    "lockout_duration": 900,                 # 15 minutes
    "password_min_length": 12,               # Security policy
    "rate_limit_per_ip": 100,                # Requests per hour
    "auth_attempts_per_15min": 5,            # Login attempts per 15min
    "tenant_id_header": "X-BAS-Tenant",      # Tenant header name
    "allow_session_fallback": true            # Allow session when JWT fails/missing
}
```

### Mode Options
- **`"disabled"`**: No authentication (development only)
- **`"shadow"`**: Log auth attempts but don't block (testing)
- **`"user_password"`**: Full authentication required (production); JWT preferred, session fallback optional

### Provider Selection (Server Config)
- Auth provider wired via server configuration (e.g., `auth0`, `mock`, deny-all)
- Health exposed at `GET /api/health/auth`

### Rate Limiting (Server Config)
- Request-level token-bucket (per-tenant/per-version)
- Per-user sliding window (Redis), configurable per endpoint via admin API
