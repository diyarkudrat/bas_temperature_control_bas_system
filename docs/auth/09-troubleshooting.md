# Troubleshooting Guide

## 🔍 Troubleshooting Guide

### Common Issues

#### "Session object has no attribute 'get'" Error
**Problem**: Code trying to access session as dictionary instead of object
**Solution**: Use `session.username` instead of `session.get('username')`

#### "Authentication required" on every request
**Problem**: Missing session token
**Solution**: Include `X-Session-ID` header or ensure cookie is set

#### "Invalid session ID format"
**Problem**: Malformed session token
**Solution**: Check token format - should start with "sess_" and be 32+ characters

#### Rate limiting too aggressive
**Problem**: Legitimate users getting locked out
**Solution**: Adjust `auth_attempts_per_15min` and `lockout_duration` in config

### Debugging Tips

1. **Check logs**: All auth events are logged with timestamps
2. **Database queries**: Check `sessions` and `audit_log` tables
3. **Session state**: Use `/auth/status` endpoint to check session validity
4. **Rate limits**: Check `rate_limiter.attempts` in memory
