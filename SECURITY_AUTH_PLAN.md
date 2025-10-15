# BAS System Authentication Enhancement Plan

## Overview

This document outlines a comprehensive plan to enhance the authentication system for the BAS (Building Automation System) temperature controller. The goal is to make the system more secure while keeping it simple and compatible with the Raspberry Pi Pico W's limited resources.

## Current Situation

### What We Have Now
- Basic token authentication using query parameters (`?token=xxx`)
- Simple password hashing with a fixed salt
- No way to rotate or revoke tokens
- No access control (all tokens have full access)
- Some security vulnerabilities that need fixing

### Problems We Need to Solve
1. **Security Issues**
   - Hardcoded salt that's the same for all tokens
   - Test tokens stored in source code
   - Real credentials in untracked files
   - No way to revoke compromised tokens

2. **Missing Features**
   - No token expiration
   - No access levels (read-only vs full access)
   - No audit logging
   - No rate limiting on failed attempts

## Security Benefits

### Before (Current Issues)
- ❌ Same salt for all tokens
- ❌ No way to revoke tokens
- ❌ No access control
- ❌ Tokens in query parameters (visible in logs)
- ❌ No audit trail

### After (Enhanced Security)
- ✅ Unique salt per token
- ✅ Immediate token revocation
- ✅ Granular access control
- ✅ Header-based authentication
- ✅ Complete audit logging
- ✅ Rate limiting and lockout
- ✅ Token expiration

## Proposed Solution

### Design Choice: User/Password + SMS MFA Authentication

We'll implement a modern authentication system that combines:
- **Username/Password authentication** for user identification
- **SMS MFA via Twilio** for two-factor authentication
- **Session-based access** with automatic expiration
- **Operator-focused interface** for temperature control
- **Secure session management** with audit logging

### Why This Approach?
- **User-friendly**: Familiar login process for operators
- **Secure**: Two-factor authentication via SMS
- **Modern**: Session-based authentication like web applications
- **Practical**: Works with existing Pico W constraints
- **Auditable**: Track who made what changes and when

## How It Will Work

### 1. Authentication Flow
```
1. User submits username/password → POST /auth/login
2. System validates credentials → Generate 6-digit SMS code
3. User receives SMS via Twilio → Enters code via POST /auth/verify
4. System issues session token → User can access protected endpoints
5. Session expires after 30 minutes → Re-authentication required
```

### 2. User Roles
- **Operator**: Can view status and change temperature setpoints
- **Admin**: Full system access including user management
- **Read-only**: Can view status and telemetry (future expansion)

### 3. Security Features
- **Two-factor authentication**: Username/password + SMS MFA
- **Session-based access**: No permanent tokens, automatic expiration
- **Rate limiting**: Block IPs after too many failed attempts
- **Audit logging**: Track all authentication events and system changes
- **Secure session management**: Automatic cleanup of expired sessions

## Implementation Plan

### Phase 1: Core Authentication System
- Implement user/password authentication
- Add Twilio SMS integration for MFA
- Create session management system
- Add audit logging for authentication events

### Phase 2: Security Enhancements
- Add rate limiting for failed login attempts
- Implement session timeout and cleanup
- Add user management capabilities
- Create security monitoring and alerts

### Phase 3: Integration and Testing
- Integrate with existing temperature control endpoints
- Test authentication flow end-to-end
- Implement gradual rollout with fallback options
- Monitor system performance and security

## Configuration

### User Database (`users.json`)
```json
{
  "users": {
    "operator1": {
      "username": "operator1",
      "password_hash": "hashed_password_here",
      "salt": "random_salt_here",
      "phone_number": "+1234567890",
      "role": "operator",
      "created_at": 1700000000,
      "last_login": 0,
      "failed_attempts": 0,
      "locked_until": 0
    },
    "admin": {
      "username": "admin",
      "password_hash": "hashed_admin_password",
      "salt": "admin_salt_here",
      "phone_number": "+1987654321",
      "role": "admin",
      "created_at": 1700000000,
      "last_login": 0,
      "failed_attempts": 0,
      "locked_until": 0
    }
  }
}
```

### Twilio SMS Configuration (`secrets.json`)
```json
{
  "twilio": {
    "account_sid": "your_twilio_account_sid",
    "auth_token": "your_twilio_auth_token",
    "from_number": "+1234567890"
  },
  "auth_settings": {
    "session_timeout": 1800,
    "mfa_code_expiry": 300,
    "max_login_attempts": 5,
    "lockout_duration": 900,
    "password_min_length": 8
  }
}
```

### Feature Flags
```python
# Enable/disable authentication
AUTH_ENABLED = True

# Choose authentication mode
AUTH_MODE = "user_password_mfa"  # "simple", "enhanced", or "user_password_mfa"

# Security settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MS = 300000  # 5 minutes
SESSION_TIMEOUT_MS = 1800000  # 30 minutes
```

## API Endpoints

### Authentication Endpoints

#### 1. POST /auth/login
**Purpose**: Authenticate user with username/password and initiate MFA process

**Request Body**:
```json
{
  "username": "operator1",
  "password": "user_password",
  "phone_number": "+1234567890"
}
```

**Response (Success)**:
```json
{
  "status": "mfa_required",
  "message": "MFA code sent to your phone",
  "expires_in": 300
}
```

**Response (Error)**:
```json
{
  "error": "Invalid credentials",
  "code": "AUTH_FAILED"
}
```

**Possible Error Codes**:
- `AUTH_FAILED`: Invalid username/password
- `USER_LOCKED`: Account locked due to too many failed attempts
- `SMS_FAILED`: Failed to send SMS code
- `MISSING_FIELDS`: Required fields missing

#### 2. POST /auth/verify
**Purpose**: Verify MFA code and create authenticated session

**Request Body**:
```json
{
  "username": "operator1",
  "code": "123456"
}
```

**Response (Success)**:
```json
{
  "status": "success",
  "session_id": "sess_abc123def456",
  "expires_in": 1800,
  "user": {
    "username": "operator1",
    "role": "operator"
  }
}
```

**Response (Error)**:
```json
{
  "error": "Invalid MFA code",
  "code": "MFA_FAILED"
}
```

**Possible Error Codes**:
- `MFA_FAILED`: Invalid or expired MFA code
- `MFA_EXPIRED`: MFA code has expired
- `SESSION_CREATE_FAILED`: Failed to create session

#### 3. POST /auth/logout
**Purpose**: Terminate user session

**Request Body**:
```json
{
  "session_id": "sess_abc123def456"
}
```

**Response (Success)**:
```json
{
  "status": "success",
  "message": "Logged out successfully"
}
```

**Response (Error)**:
```json
{
  "error": "Invalid session",
  "code": "SESSION_INVALID"
}
```

#### 4. GET /auth/status
**Purpose**: Check session validity and get user info

**Headers**:
```
X-Session-ID: sess_abc123def456
```

**Response (Valid Session)**:
```json
{
  "status": "valid",
  "user": {
    "username": "operator1",
    "role": "operator",
    "login_time": 1700000000
  },
  "expires_in": 1200
}
```

**Response (Invalid Session)**:
```json
{
  "error": "Session expired",
  "code": "SESSION_EXPIRED"
}
```

### Protected Endpoints

#### 5. POST /set (Enhanced)
**Purpose**: Update temperature setpoint (requires authentication)

**Headers**:
```
X-Session-ID: sess_abc123def456
Content-Type: application/json
```

**Request Body**:
```json
{
  "sp": 250,
  "db": 10
}
```

**Response (Success)**:
```json
{
  "status": "success",
  "updated": {
    "setpoint_tenths": 250,
    "deadband_tenths": 10
  },
  "updated_by": "operator1",
  "timestamp": 1700000000
}
```

**Response (Authentication Required)**:
```json
{
  "error": "Authentication required",
  "message": "Please login with username/password and MFA",
  "code": "AUTH_REQUIRED"
}
```

**Response (Insufficient Permissions)**:
```json
{
  "error": "Insufficient permissions",
  "message": "Operator role cannot perform this action",
  "code": "PERMISSION_DENIED"
}
```

### System Endpoints (Unauthenticated)

#### 6. GET /status
**Purpose**: Get current system status (no authentication required)

**Response**:
```json
{
  "temp_tenths": 235,
  "setpoint_tenths": 250,
  "deadband_tenths": 10,
  "state": "IDLE",
  "cool_active": false,
  "heat_active": true,
  "sensor_ok": true,
  "alarm": false,
  "error_code": 0,
  "timestamp": 1700000000
}
```

#### 7. GET /auth/info
**Purpose**: Get authentication system information

**Response**:
```json
{
  "auth_enabled": true,
  "auth_mode": "user_password_mfa",
  "session_timeout": 1800,
  "mfa_code_expiry": 300,
  "max_login_attempts": 5,
  "lockout_duration": 900
}
```

### Error Response Format

All endpoints return consistent error responses:

```json
{
  "error": "Human-readable error message",
  "code": "ERROR_CODE",
  "details": {
    "field": "Additional error details",
    "timestamp": 1700000000
  }
}
```

**Common Error Codes**:
- `AUTH_REQUIRED`: Authentication required
- `AUTH_FAILED`: Authentication failed
- `SESSION_EXPIRED`: Session has expired
- `PERMISSION_DENIED`: Insufficient permissions
- `RATE_LIMITED`: Too many requests
- `INVALID_REQUEST`: Malformed request
- `INTERNAL_ERROR`: Server error

## Usage Examples

### Authentication Flow
```bash
# Step 1: Login with username/password
curl -X POST http://192.168.1.129/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "operator1",
    "password": "user_password",
    "phone_number": "+1234567890"
  }'

# Response: {"status": "mfa_required", "message": "MFA code sent to your phone"}

# Step 2: Verify MFA code (after receiving SMS)
curl -X POST http://192.168.1.129/auth/verify \
  -H "Content-Type: application/json" \
  -d '{
    "username": "operator1",
    "code": "123456"
  }'

# Response: {"status": "success", "session_id": "sess_abc123def456", "expires_in": 1800}
```

### Using Authenticated Session
```bash
# Step 3: Use session to control temperature
curl -X POST http://192.168.1.129/set \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: sess_abc123def456" \
  -d '{"sp": 250, "db": 10}'

# Response: {"status": "success", "updated": {"setpoint_tenths": 250}, "updated_by": "operator1"}
```

### Session Management
```bash
# Check session status
curl -H "X-Session-ID: sess_abc123def456" http://192.168.1.129/auth/status

# Logout
curl -X POST http://192.168.1.129/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"session_id": "sess_abc123def456"}'
```

## Backward Compatibility

### Gradual Rollout
1. **Stage 0**: Auth disabled (current state)
2. **Stage 1**: Shadow mode (log but don't block)
3. **Stage 2**: Enforced authentication

## Testing Plan

### Security Tests
- [ ] Timing attack resistance
- [ ] Token validation accuracy
- [ ] Rate limiting effectiveness
- [ ] Memory usage under load

### Functionality Tests
- [ ] Token creation and rotation
- [ ] Access level enforcement
- [ ] Audit logging accuracy
- [ ] Backward compatibility

### Integration Tests
- [ ] Real device testing
- [ ] Multiple client scenarios
- [ ] Token expiration handling
- [ ] System recovery from failures

## Monitoring and Maintenance

### What to Monitor
- Authentication success/failure rates
- Token usage patterns
- Memory usage of auth system
- Failed attempt patterns

### Regular Maintenance
- Clean up expired tokens
- Review audit logs
- Rotate admin tokens
- Update security settings

## Risk Assessment

### Low Risk
- **Timing attacks**: Already protected with constant-time comparison
- **Memory usage**: Designed for minimal footprint
- **Performance**: O(1) token lookup

### Medium Risk
- **Token leakage**: Mitigated by header-based auth and audit logging
- **Brute force**: Protected by rate limiting and lockout
- **Clock skew**: Graceful handling of timestamp issues

### High Risk (Mitigated)
- **Token compromise**: Immediate revocation capability
- **Scope escalation**: Strict access level enforcement
- **System overload**: Rate limiting and connection limits

## Success Criteria

### Security Goals
- ✅ No hardcoded secrets in source code
- ✅ Two-factor authentication (password + SMS)
- ✅ Session-based access with automatic expiration
- ✅ Rate limiting and account lockout protection
- ✅ Complete audit trail of all authentication events
- ✅ Secure password hashing with unique salts

### Performance Goals
- ✅ < 5ms session validation time
- ✅ < 1KB memory per active session
- ✅ No impact on control loop performance
- ✅ Graceful degradation under load
- ✅ Efficient SMS delivery via Twilio

### Usability Goals
- ✅ Simple username/password login
- ✅ Clear error messages and status codes
- ✅ Mobile-friendly authentication flow
- ✅ Automatic session timeout
- ✅ Easy user management

## Conclusion

This plan provides a modern, user-friendly authentication solution for the BAS system that combines security with usability. The user/password + SMS MFA approach offers:

- **Modern Security**: Two-factor authentication with SMS verification
- **User-Friendly**: Familiar login process for operators
- **Secure**: Session-based access with automatic expiration
- **Practical**: Works within Pico W constraints while providing enterprise-grade security
- **Auditable**: Complete tracking of who made what changes and when

The system transforms the BAS controller from a simple device with basic token auth into a modern, secure system that operators can easily use while maintaining the highest security standards.
