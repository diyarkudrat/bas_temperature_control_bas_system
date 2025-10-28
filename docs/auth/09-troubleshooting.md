# Troubleshooting Guide

## 🔍 Troubleshooting Guide

### Common Issues

#### "Authorization required" or JWT rejected
**Problem**: Missing/invalid `Authorization: Bearer <JWT>` and session fallback disabled
**Solution**: Provide a valid JWT or enable `allow_session_fallback` to permit session usage

#### "Session object has no attribute 'get'" Error
**Problem**: Code trying to access session as dictionary instead of object
**Solution**: Use `session.username` instead of `session.get('username')`

#### "Authentication required" on every request
**Problem**: Missing session token
**Solution**: Include `X-Session-ID` header or ensure cookie is set

#### "Invalid session ID format"
**Problem**: Malformed session token
**Solution**: Check token format - should start with "sess_" and be 32+ characters

#### "Token revoked" with 403
**Problem**: Token `jti` revoked
**Solution**: Obtain a new token; validate revocation service configuration

#### Rate limiting too aggressive
**Problem**: Legitimate users getting locked out
**Solution**: Adjust `auth_attempts_per_15min` and `lockout_duration` in config

### Debugging Tips

1. **Check logs**: All auth events are logged with timestamps
2. **Database queries**: Check `sessions` and `audit_log` tables
3. **Session state**: Use `/auth/status` endpoint to check session validity
4. **Rate limits**: Inspect `per_user_limits` snapshot via `POST /auth/limits`
5. **Provider health**: Check `/api/health/auth` for provider status
