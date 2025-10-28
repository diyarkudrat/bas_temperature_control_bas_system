# Testing the System

## 🧪 Testing the System

### Manual Testing
```bash
# 1. Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Admin123!@#X"}'

# 2a. Use session (cookie will be set automatically)
curl -X POST http://localhost:8080/api/set_setpoint \
  -H "Content-Type: application/json" \
  -d '{"setpoint_tenths": 250, "deadband_tenths": 10}'

# 2b. Or use X-Session-ID header
curl -X POST http://localhost:8080/api/set_setpoint \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: sess_your_session_token_here" \
  -d '{"setpoint_tenths": 250}'

# 2c. Or use JWT (preferred)
curl -X POST http://localhost:8080/api/set_setpoint \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGci..." \
  -d '{"setpoint_tenths": 250}'

# 3. Check session status
curl http://localhost:8080/auth/status

# 4. Logout
curl -X POST http://localhost:8080/auth/logout
```

### Automated Testing
```bash
# Run the complete test suite
python3 test_auth_complete.py

# Test individual components
python3 test_auth_flow.py
```
