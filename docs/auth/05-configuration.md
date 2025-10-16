# Configuration

## 🔧 Configuration Explained

### Authentication Modes
```python
# In config/auth_config.json
{
    "auth_enabled": true,                    # Master switch
    "auth_mode": "user_password",            # Current mode
    "session_timeout": 1800,                 # 30 minutes
    "max_concurrent_sessions": 3,            # Per user limit
    "max_login_attempts": 5,                 # Before lockout
    "lockout_duration": 900,                 # 15 minutes
    "password_min_length": 12,               # Security policy
    "rate_limit_per_ip": 100,                # Requests per hour
    "auth_attempts_per_15min": 5             # Login attempts per 15min
}
```

### Mode Options
- **`"disabled"`**: No authentication (development only)
- **`"shadow"`**: Log auth attempts but don't block (testing)
- **`"user_password"`**: Full authentication required (production)
