# BAS Authentication System - Setup & Operations Guide

## 🎯 What This System Does

The BAS authentication system provides **secure access control** for your temperature controller. Think of it as a digital security guard that:

- Verifies user identity with username/password
- Issues temporary access tokens (sessions)
- Controls who can change temperature settings
- Tracks all access attempts for security monitoring

---

## 🚀 Quick Start (5 Minutes)

### Step 1: Start the Server
```bash
cd server
source venv/bin/activate
python3 bas_server.py
```

### Step 2: Test Authentication
```bash
# Test the complete authentication flow
python3 test_auth_complete.py

# Test individual components
python3 test_auth_flow.py
```

### Step 3: Try It Out
```bash
# Login as admin
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Admin123!@#X"}'

# Check session status
curl http://localhost:8080/auth/status
```

**That's it!** The system is now running with authentication enabled.

---

## ⚙️ Configuration Explained

### Main Configuration File (`config/auth_config.json`)
```json
{
    "auth_enabled": true,                    // Master switch - turn auth on/off
    "auth_mode": "user_password",            // Authentication type
    "session_timeout": 1800,                 // Session expires after 30 minutes
    "max_concurrent_sessions": 3,            // Max 3 sessions per user
    "max_login_attempts": 5,                 // Lock account after 5 failed attempts
    "lockout_duration": 900,                 // Lock for 15 minutes
    "password_min_length": 12,               // Minimum password strength
    "rate_limit_per_ip": 100,                // Max 100 requests per hour per IP
    "auth_attempts_per_15min": 5             // Max 5 login attempts per 15 minutes
}
```

### Authentication Modes
- **`"disabled"`**: No authentication (development only)
- **`"shadow"`**: Log attempts but don't block (testing/debugging)
- **`"user_password"`**: Full authentication required (production)

### Alternative: Environment Variables
Instead of JSON files, you can use environment variables:

```bash
# Copy the template
cp config/auth.example.env .env

# Edit with your settings
export BAS_AUTH_ENABLED=true
export BAS_AUTH_MODE=user_password
export BAS_SESSION_TIMEOUT=1800
```

---

## 👤 Default Users

The system comes with a pre-configured admin user:

| Field | Value |
|-------|-------|
| **Username** | `admin` |
| **Password** | `Admin123!@#X` |
| **Role** | `admin` (full access) |

**⚠️ Important**: Change this password immediately in production!

---

## 🔌 API Reference

### Authentication Endpoints

#### `POST /auth/login`
**Purpose**: Log in with username/password

**Request**:
```json
{
    "username": "admin",
    "password": "Admin123!@#X"
}
```

**Success Response**:
```json
{
    "status": "success",
    "expires_in": 1800,
    "user": {
        "username": "admin",
        "role": "admin"
    }
}
```
*Also sets a secure cookie with the session token*

**Error Responses**:
- `400`: Missing username/password
- `401`: Invalid credentials
- `423`: Account locked (too many failed attempts)
- `429`: Rate limited (too many attempts from IP)

#### `GET /auth/status`
**Purpose**: Check if your session is still valid

**Request**: Session token in cookie or `X-Session-ID` header

**Success Response**:
```json
{
    "status": "valid",
    "user": {
        "username": "admin",
        "role": "admin",
        "login_time": 1700000000
    },
    "expires_in": 1200
}
```

#### `POST /auth/logout`
**Purpose**: End your session

**Request**: Session token in cookie or `X-Session-ID` header

**Response**:
```json
{
    "status": "success",
    "message": "Logged out successfully"
}
```

### Protected Endpoints (Require Authentication)

#### `POST /set` - Temperature Control
**Purpose**: Change temperature setpoint (requires operator+ role)

**Headers**:
```
X-Session-ID: sess_abc123def456...
Content-Type: application/json
```

**Request**:
```json
{
    "sp": 250,    // Setpoint: 25.0°C (in tenths)
    "db": 10      // Deadband: 1.0°C (in tenths)
}
```

**Success Response**:
```json
{
    "status": "success",
    "updated": {
        "setpoint_tenths": 250,
        "deadband_tenths": 10
    },
    "updated_by": "admin",
    "timestamp": 1700000000
}
```

#### `GET /api/telemetry` - View Data
**Purpose**: Get telemetry data (requires authentication)

**Headers**: Session token in cookie or `X-Session-ID` header

**Response**:
```json
{
    "temperature": 235,
    "setpoint": 250,
    "state": "HEATING",
    "timestamp": 1700000000
}
```

---

## 🛡️ Security Features

### Password Security
- **Strong Hashing**: PBKDF2-SHA256 with 100,000 iterations
- **Unique Salts**: Each password gets its own random salt
- **Password Policy**: 12+ characters, mixed case, numbers, symbols
- **History Tracking**: Prevents reusing recent passwords

### Session Security
- **Secure Tokens**: Cryptographically secure session IDs
- **Fingerprinting**: Sessions tied to browser/device characteristics
- **Automatic Expiry**: Sessions expire after 30 minutes of inactivity
- **Concurrent Limits**: Maximum 3 active sessions per user
- **HttpOnly Cookies**: Session tokens can't be accessed by JavaScript

### Rate Limiting & Lockout
- **IP Rate Limiting**: Max 5 failed attempts per 15 minutes per IP
- **Account Lockout**: Accounts locked after 5 failed attempts
- **Automatic Recovery**: Lockouts expire after 15 minutes
- **Progressive Delays**: Longer delays after repeated failures

### Audit Logging
- **Complete Trail**: Every authentication event is logged
- **Structured Data**: JSON format for easy analysis
- **Performance Indexed**: Fast queries even with large log volumes
- **Security Monitoring**: Failed attempts, lockouts, suspicious activity

---

## 🔧 User Management

### Using the Admin Script
```bash
# Create a new user
python3 scripts/auth_admin.py create-user john "SecurePass123!" --role operator

# List all users
python3 scripts/auth_admin.py list-users

# Reset a password
python3 scripts/auth_admin.py reset-password john "NewSecurePass123!"

# Unlock a locked account
python3 scripts/auth_admin.py unlock-user john

# Delete a user
python3 scripts/auth_admin.py delete-user john

# Get help
python3 scripts/auth_admin.py --help
```

### User Roles Explained
- **`admin`**: Full system access, can manage users
- **`operator`**: Can control temperature, view data
- **`read-only`**: Can view data only, cannot make changes

---

## 🐛 Troubleshooting Guide

### Common Issues & Solutions

#### 1. "Authentication required" on every request
**Problem**: Missing session token
**Solution**: 
- Check that login was successful (should return session cookie)
- Include `X-Session-ID` header in requests
- Ensure cookies are enabled in your client

#### 2. "Invalid session ID format"
**Problem**: Malformed session token
**Solution**: 
- Session tokens should start with "sess_" and be 32+ characters
- Check that the token wasn't truncated or modified
- Try logging in again to get a fresh token

#### 3. "Account locked" error
**Problem**: Too many failed login attempts
**Solution**:
- Wait 15 minutes for automatic unlock
- Use admin script to manually unlock: `python3 scripts/auth_admin.py unlock-user username`
- Check if someone is trying to brute force the account

#### 4. "Rate limited" error
**Problem**: Too many requests from your IP
**Solution**:
- Wait for the rate limit to reset (usually 15 minutes)
- Check if multiple clients are using the same IP
- Adjust rate limits in configuration if needed

#### 5. Session expires too quickly
**Problem**: Sessions timing out faster than expected
**Solution**:
- Check `session_timeout` setting in config (default: 1800 seconds = 30 minutes)
- Sessions reset their timer on each request
- Consider increasing timeout for longer work sessions

### Debugging Steps

1. **Check the logs**: All auth events are logged with timestamps
   ```bash
   tail -f server.log | grep -i auth
   ```

2. **Verify configuration**: Make sure auth is enabled and configured correctly
   ```bash
   python3 -c "from auth.config import AuthConfig; print(AuthConfig.from_file('config/auth_config.json'))"
   ```

3. **Test with curl**: Use curl to test endpoints manually
   ```bash
   # Test login
   curl -v -X POST http://localhost:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "Admin123!@#X"}'
   ```

4. **Check database**: Look at the sessions and audit_log tables
   ```bash
   sqlite3 bas_telemetry.db "SELECT * FROM sessions;"
   sqlite3 bas_telemetry.db "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 10;"
   ```

---

## 🧪 Testing the System

### Automated Testing
```bash
# Run the complete test suite
python3 test_auth_complete.py

# Test individual components
python3 test_auth_flow.py

# Test with different scenarios
python3 -m pytest tests/unit/auth/ -v
```

### Manual Testing Checklist
- [ ] Can login with valid credentials
- [ ] Cannot login with invalid credentials
- [ ] Account locks after 5 failed attempts
- [ ] Session expires after timeout
- [ ] Protected endpoints require authentication
- [ ] Role-based permissions work correctly
- [ ] Logout invalidates session
- [ ] Rate limiting prevents abuse

### Load Testing
```bash
# Test concurrent sessions
for i in {1..10}; do
  curl -X POST http://localhost:8080/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "Admin123!@#X"}' &
done
wait
```

---

## 📊 Monitoring & Maintenance

### Key Metrics to Monitor
- **Login Success Rate**: Should be > 95% for legitimate users
- **Average Session Duration**: Should match expected usage patterns
- **Failed Login Attempts**: Sudden spikes may indicate attacks
- **Rate Limit Hits**: Should be rare for normal usage
- **Account Lockouts**: Should be infrequent

### Regular Maintenance Tasks

#### Daily
- [ ] Check logs for failed authentication attempts
- [ ] Monitor session usage patterns
- [ ] Verify system performance

#### Weekly
- [ ] Review audit logs for suspicious activity
- [ ] Check for locked accounts that need manual unlock
- [ ] Verify backup of user database

#### Monthly
- [ ] Rotate admin passwords
- [ ] Review and update rate limiting settings
- [ ] Clean up old audit logs (if needed)
- [ ] Update security documentation

### Log Analysis Examples
```bash
# Count failed login attempts today
grep "$(date +%Y-%m-%d)" server.log | grep "LOGIN_FAILURE" | wc -l

# Find most active users
sqlite3 bas_telemetry.db "SELECT username, COUNT(*) as sessions FROM sessions GROUP BY username ORDER BY sessions DESC;"

# Check for suspicious IPs
sqlite3 bas_telemetry.db "SELECT ip_address, COUNT(*) as attempts FROM audit_log WHERE action='LOGIN_FAILURE' GROUP BY ip_address ORDER BY attempts DESC LIMIT 10;"
```

---

## 🚀 Production Deployment

### Pre-Deployment Checklist
- [ ] Change default admin password
- [ ] Configure HTTPS/SSL certificates
- [ ] Set up log rotation
- [ ] Configure backup for user database
- [ ] Test failover scenarios
- [ ] Document emergency procedures

### Security Hardening
```bash
# 1. Change default password
python3 scripts/auth_admin.py reset-password admin "YourSecurePassword123!"

# 2. Create additional admin users
python3 scripts/auth_admin.py create-user backup_admin "AnotherSecurePass123!" --role admin

# 3. Review and tighten configuration
# Edit config/auth_config.json to reduce session timeout, increase password requirements

# 4. Set up monitoring alerts
# Configure alerts for multiple failed logins, account lockouts, etc.
```

### Performance Tuning
- **Session Cache**: Sessions are cached in memory for fast access
- **Database Indexes**: Audit logs are indexed for fast queries
- **Connection Pooling**: SQLite handles concurrent access efficiently
- **Rate Limiting**: Prevents system overload from abuse

---

## 🆘 Emergency Procedures

### Account Recovery
If you're locked out of all admin accounts:
1. Stop the server
2. Manually unlock accounts in database:
   ```bash
   sqlite3 bas_telemetry.db "UPDATE users SET failed_attempts=0, locked_until=0 WHERE role='admin';"
   ```
3. Restart the server

### Disable Authentication Temporarily
If you need to disable auth in an emergency:
1. Edit `config/auth_config.json`
2. Set `"auth_enabled": false`
3. Restart the server
4. Fix the issue and re-enable auth

### Reset All Sessions
To invalidate all active sessions:
```bash
sqlite3 bas_telemetry.db "DELETE FROM sessions;"
```

---

## 📚 Additional Resources

- **Complete Engineer's Guide**: `docs/AUTH_SYSTEM_ENGINEER_GUIDE.md`
- **API Reference**: `docs/api/README.md`
- **Security Plan**: `docs/SECURITY_AUTH_PLAN.md`
- **System Overview**: `docs/SYSTEM_OVERVIEW.md`

---

## ✅ Current Status

- ✅ **Authentication system implemented and working**
- ✅ **Session management with security features**
- ✅ **Protected endpoints secured**
- ✅ **Comprehensive test suite**
- ✅ **Admin tools for user management**
- ✅ **Audit logging and monitoring**
- ✅ **Rate limiting and security features**
- ✅ **Production-ready configuration**

The authentication system is **fully operational** and ready for production use. It provides enterprise-grade security while remaining simple to understand and maintain.
