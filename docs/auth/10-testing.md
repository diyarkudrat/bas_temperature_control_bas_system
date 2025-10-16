# Testing the System

## 🧪 Testing the System

### Manual Testing
```bash
# 1. Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Admin123!@#X"}'

# 2. Use session (cookie will be set automatically)
curl -X POST http://localhost:8080/set \
  -H "Content-Type: application/json" \
  -d '{"sp": 250, "db": 10}'

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
