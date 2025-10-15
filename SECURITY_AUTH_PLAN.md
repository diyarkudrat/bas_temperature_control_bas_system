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

### Design Choice: Enhanced API Keys

We'll improve the existing system by adding:
- **Better token format**: `key_id:random_bytes` (e.g., `admin_001:def456789...`)
- **Per-token unique salts**: Each token gets its own random salt
- **Access levels**: Read-only, read-write, and admin tokens
- **Token management**: Create, rotate, and revoke tokens
- **Security features**: Rate limiting, audit logging, expiration

### Why This Approach?
- **Keeps existing code**: We enhance what's already working
- **Fits Pico W**: Minimal memory usage, no external dependencies
- **Easy to use**: Simple header-based authentication
- **Secure**: Addresses all current vulnerabilities

## How It Will Work

### 1. Token Format
```
Old: ?token=simplepassword

New: X-Api-Key: admin_001:def456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01
```

### 2. Access Levels
- **Read-only**: Can view status, telemetry, logs
- **Read-write**: Can change settings, setpoints
- **Admin**: Can rotate tokens, change profiles, full access

### 3. Security Features
- **Unique salts**: Each token has its own random salt
- **Rate limiting**: Block IPs after too many failed attempts
- **Audit logging**: Track who does what and when
- **Token expiration**: Tokens can have expiration dates
- **Immediate revocation**: Instantly disable compromised tokens

## Implementation Plan

### Phase 1:
- Create new token management system
- Add per-token unique salts
- Implement access level checking
- Add audit logging

### Phase 2:
- Add rate limiting for failed attempts
- Implement token expiration
- Add token rotation capability
- Create admin tools for token management

### Phase 3:
- Test with shadow mode (log but don't block)
- Gradually enable enforcement
- Monitor for issues
- Full deployment

## Configuration

### Token Storage (`secrets.json`)
```json
{
  "tokens": {
    "admin_001": {
      "token": "admin_001:def456789...",
      "scope": "admin",
      "expires_at": 0,
      "description": "Admin token"
    },
    "read_001": {
      "token": "read_001:abc123456...",
      "scope": "read",
      "expires_at": 1735689600,
      "description": "Read-only token"
    }
  },
  "settings": {
    "auth_enabled": true,
    "max_failed_attempts": 5,
    "lockout_duration_ms": 300000
  }
}
```

### Feature Flags
```python
# Enable/disable authentication
AUTH_ENABLED = True

# Choose authentication mode
AUTH_MODE = "enhanced"  # "simple" or "enhanced"

# Security settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MS = 300000  # 5 minutes
```

## Usage Examples

### Creating Tokens
```bash
# Create admin token
python tools/token_admin.py create --scope admin --description "Admin access"

# Create read-only token with expiration
python tools/token_admin.py create --scope read --expires 2024-12-31 --description "Read-only access"
```

### Using Tokens
```bash
# Get system status (read-only)
curl -H "X-Api-Key: read_001:abc123456..." http://192.168.1.129/status

# Change temperature (read-write)
curl -H "X-Api-Key: admin_001:def456789..." http://192.168.1.129/set \
  -H "Content-Type: application/json" \
  -d '{"sp": 250}'
```

### Managing Tokens
```bash
# List all tokens
python tools/token_admin.py list

# Revoke a token
python tools/token_admin.py revoke admin_001

# Rotate a token (create new, revoke old)
python tools/token_admin.py rotate admin_001
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
- ✅ All tokens have unique salts
- ✅ Immediate token revocation capability
- ✅ Granular access control
- ✅ Complete audit trail

### Performance Goals
- ✅ < 5ms token validation time
- ✅ < 2KB memory for 10 tokens
- ✅ No impact on control loop performance
- ✅ Graceful degradation under load

### Usability Goals
- ✅ Simple token management
- ✅ Clear error messages
- ✅ Backward compatibility
- ✅ Easy deployment

## Conclusion

This plan provides a comprehensive solution to enhance the BAS system's authentication while maintaining compatibility with the Pico W's constraints. The approach is:

- **Secure**: Addresses all current vulnerabilities
- **Simple**: Easy to understand and maintain
- **Compatible**: Works with existing code
- **Scalable**: Can grow with future needs
