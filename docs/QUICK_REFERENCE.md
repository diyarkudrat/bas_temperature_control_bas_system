# BAS System Quick Reference

**Essential commands, endpoints, and troubleshooting for the BAS Temperature Controller.**

## 🚀 Quick Start Commands

### System Operations
```bash
# Start complete system (server + hardware)
./scripts/start_bas.sh

# Start server only
./scripts/start_bas.sh --server-only

# Start hardware only (Pico W)
./scripts/start_bas.sh --hardware-only

# Check system status
./scripts/status_bas.sh

# Stop system
./scripts/stop_bas.sh

# System health check
./verify_system.sh
```

### Authentication Management
```bash
# Create new user
python3 scripts/auth_admin.py create-user <username> <password> <phone> --role <role>

# List all users
python3 scripts/auth_admin.py list-users

# Reset password
python3 scripts/auth_admin.py reset-password <username> <new_password>

# Unlock user account
python3 scripts/auth_admin.py unlock-user <username>
```

---

## 🌐 Essential API Endpoints

### System Status (No Auth Required)
```bash
# Get system status
curl http://localhost:8080/api/status

# Health check
curl http://localhost:8080/api/health

# Get configuration
curl http://localhost:8080/api/config
```

### Authentication Flow
```bash
# Step 1: Login (gets MFA code)
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password", "phone": "+1234567890"}'

# Step 2: Verify MFA code (gets session token)
curl -X POST http://localhost:8080/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "code": "123456"}'

# Step 3: Use session token for protected endpoints
curl -X POST http://localhost:8080/api/set_setpoint \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: sess_your_token_here" \
  -d '{"setpoint_tenths": 250, "deadband_tenths": 10}'
```

### Temperature Control (Auth Required)
```bash
# Set temperature setpoint
curl -X POST http://localhost:8080/api/set_setpoint \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: sess_your_token_here" \
  -d '{"setpoint_tenths": 250, "deadband_tenths": 10}'

# Get telemetry data
curl "http://localhost:8080/api/telemetry?limit=50" \
  -H "X-Session-ID: sess_your_token_here"
```

---

## 🔧 Configuration Quick Reference

### Default Credentials
- **Admin User**: `admin` / `Admin123!@#X` (change immediately!)
- **Base URL**: `http://localhost:8080/`
- **Database**: `server/bas_telemetry.db`

### Key Configuration Files
- **Auth Config**: `config/auth_config.json`
- **Secrets**: `config/secrets.json` (Twilio credentials)
- **Server Config**: `server/config/auth_config.json`

### Environment Variables
```bash
# Authentication settings
export AUTH_ENABLED=true
export AUTH_MODE=user_password_mfa
export SESSION_TIMEOUT=1800

# Twilio settings
export TWILIO_ACCOUNT_SID=your_sid
export TWILIO_AUTH_TOKEN=your_token
export TWILIO_FROM_NUMBER=+1234567890
```

---

## 🐛 Common Troubleshooting

### System Won't Start
```bash
# Check system status
./scripts/status_bas.sh

# Check server logs
tail -f server/logs/server.log

# Verify system health
./verify_system.sh
```

### Authentication Issues
```bash
# Check auth status
curl http://localhost:8080/auth/info

# List users
python3 scripts/auth_admin.py list-users

# Check session status
curl -H "X-Session-ID: your_token" http://localhost:8080/auth/status
```

### Hardware Issues
```bash
# Check hardware status
./scripts/status_hardware.sh --verbose

# Restart hardware
./scripts/stop_hardware.sh && ./scripts/start_hardware.sh

# Check Pico W connection
mpremote connect /dev/ttyACM* exec "import network; print(network.WLAN().ifconfig())"
```

### Network Issues
```bash
# Check server connectivity
curl http://localhost:8080/api/health

# Check Pico W WiFi
mpremote connect /dev/ttyACM* exec "import network; wlan = network.WLAN(); print(f'Connected: {wlan.isconnected()}, IP: {wlan.ifconfig()[0]}')"

# Test API from Pico W
mpremote connect /dev/ttyACM* exec "import urequests; r = urequests.get('http://192.168.1.100:8080/api/status'); print(r.text)"
```

---

## 📊 Error Codes Quick Reference

| Code | Meaning | Solution |
|------|---------|----------|
| `AUTH_REQUIRED` | Authentication needed | Login first, include X-Session-ID header |
| `AUTH_FAILED` | Invalid credentials | Check username/password |
| `SESSION_EXPIRED` | Session timed out | Re-authenticate |
| `PERMISSION_DENIED` | Insufficient permissions | Check user role |
| `RATE_LIMITED` | Too many requests | Wait before retrying |
| `INVALID_REQUEST` | Malformed request | Check JSON format |
| `MFA_FAILED` | Invalid MFA code | Request new code |
| `USER_LOCKED` | Account locked | Unlock account or wait |

---

## 🎯 User Roles & Permissions

| Role | Permissions |
|------|-------------|
| **admin** | Full system access, user management, all endpoints |
| **operator** | Temperature control, view status, telemetry access |
| **readonly** | View status and telemetry only (future) |

---

## 📱 Web Interface

### Dashboard URLs
- **Login Page**: `http://localhost:8080/auth/login`
- **Main Dashboard**: `http://localhost:8080/` (after login)
- **System Status**: `http://localhost:8080/api/status`

### Dashboard Features
- Real-time temperature graphs
- Temperature setpoint control
- System status indicators
- Telemetry data visualization
- User session management

---

## 🔒 Security Quick Reference

### Session Management
- **Session Timeout**: 30 minutes (1800 seconds)
- **MFA Code Expiry**: 5 minutes (300 seconds)
- **Max Login Attempts**: 5 before lockout
- **Lockout Duration**: 15 minutes (900 seconds)

### Security Headers
All responses include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`

---

## 📚 Related Documentation

- **[API Documentation](api/README.md)** - Complete API reference
- **[Authentication Guide](auth/README.md)** - Auth system details
- **[System Overview](SYSTEM_OVERVIEW.md)** - Architecture details
- **[Troubleshooting](auth/09-troubleshooting.md)** - Detailed troubleshooting

---

## 🆘 Emergency Procedures

### System Recovery
```bash
# Complete system restart
./scripts/stop_bas.sh
sleep 5
./scripts/start_bas.sh

# Reset authentication
python3 scripts/auth_admin.py reset-password admin newpassword

# Factory reset (if needed)
rm server/bas_telemetry.db
./setup.sh
```

### Emergency Access
- **Default Admin**: `admin` / `Admin123!@#X`
- **Bypass Auth**: Set `AUTH_ENABLED=false` in config (development only)
- **Emergency Script**: `python3 scripts/auth_admin.py unlock-user admin`

---

**💡 Tip**: Bookmark this page for quick access to essential commands and troubleshooting steps!
