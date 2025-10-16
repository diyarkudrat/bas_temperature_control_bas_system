# Authentication System Setup Guide

## Overview
This guide covers setting up the authentication system for the BAS (Building Automation System) with user/password authentication and SMS MFA.

## Quick Start

### 1. Server Setup
```bash
cd server
source venv/bin/activate
python3 bas_server.py
```

### 2. Authentication Testing
```bash
# Test basic authentication flow
python3 test_auth_flow.py

# Test complete authentication suite
python3 test_auth_complete.py
```

## Configuration

### SMS Configuration (Optional)
For production SMS MFA, configure Twilio credentials:

1. Copy the template:
```bash
cp config/templates/secrets.json.template config/secrets.json
```

2. Edit `config/secrets.json` with your Twilio credentials:
```json
{
  "twilio": {
    "account_sid": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "auth_token": "your_twilio_auth_token",
    "from_number": "+1234567890"
  }
}
```

### Default Users
The system comes with a default admin user:
- **Username**: `admin`
- **Password**: `Admin123!@#X`
- **Role**: `admin`

## API Endpoints

### Authentication Endpoints
- `POST /auth/login` - User login
- `POST /auth/verify` - MFA verification
- `POST /auth/logout` - User logout
- `GET /auth/status` - Session status

### Protected Endpoints
- `GET /api/telemetry` - Telemetry data (requires authentication)
- `POST /api/set_setpoint` - Set temperature setpoint (requires operator+ role)

## Security Features

- **Password Hashing**: PBKDF2-SHA256 with salt
- **Session Management**: Secure session tokens with expiration
- **Rate Limiting**: Protection against brute force attacks
- **Audit Logging**: All authentication events logged
- **Role-Based Access**: Admin, operator, and read-only roles

## Troubleshooting

### Common Issues

1. **"Session object has no attribute 'get'" error**
   - **Fixed**: Updated session access in telemetry endpoints
   - **Status**: ✅ Resolved

2. **SMS not configured**
   - **Solution**: Configure Twilio credentials in `config/secrets.json`
   - **Workaround**: System works without SMS (bypasses MFA for testing)

3. **Authentication required errors**
   - **Solution**: Include `X-Session-ID` header in requests
   - **Example**: `curl -H "X-Session-ID: your_session_id" http://localhost:8080/api/telemetry`

### Testing Authentication

```bash
# Test complete flow
python3 test_auth_complete.py

# Test individual components
python3 test_auth_flow.py
```

## Production Deployment

1. **Configure Twilio**: Add SMS credentials for MFA
2. **Update Passwords**: Change default admin password
3. **Enable HTTPS**: Use SSL certificates for production
4. **Monitor Logs**: Check `server.log` for authentication events

## Admin Tools

Use the admin script for user management:
```bash
python3 scripts/auth_admin.py --help
```

## Status
- ✅ Authentication system implemented
- ✅ Session management working
- ✅ Protected endpoints secured
- ✅ Test suite passing
- ⚠️ SMS MFA requires Twilio configuration
