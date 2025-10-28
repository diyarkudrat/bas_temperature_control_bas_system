# Client Examples

## 📱 Client Examples

### **Python**
```python
import requests

# Get status (no auth required)
response = requests.get('http://localhost:8080/api/status')
status = response.json()

# Set temperature (auth required) — Bearer token (preferred)
jwt_token = "eyJhbGci..."
response = requests.post(
    'http://localhost:8080/api/set_setpoint',
    headers={'Authorization': f'Bearer {jwt_token}'},
    json={'setpoint_tenths': 250, 'deadband_tenths': 10}
)

# Get telemetry data (auth required)
response = requests.get(
    'http://localhost:8080/api/telemetry?limit=50',
    headers={'Authorization': f'Bearer {jwt_token}'}
)
telemetry = response.json()
```

> **Session fallback example**
> ```python
> session_token = "sess_your_session_token_here"
> requests.post(
>   'http://localhost:8080/api/set_setpoint',
>   headers={'X-Session-ID': session_token},
>   json={'setpoint_tenths': 250}
> )
> ```

> **🔐 Authentication Examples**: For authentication examples (login, logout, protected endpoints), see [Authentication Testing](../auth/10-testing.md).

### **JavaScript**
```javascript
const jwtToken = 'eyJhbGci...';

// Get system status (no auth required)
fetch('http://localhost:8080/api/status')
  .then(response => response.json())
  .then(data => console.log(data));

// Set temperature (auth required)
fetch('http://localhost:8080/api/set_setpoint', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${jwtToken}`
  },
  body: JSON.stringify({
    setpoint_tenths: 250,
    deadband_tenths: 10
  })
});

// Get telemetry data (auth required)
fetch('http://localhost:8080/api/telemetry?limit=50', {
  headers: {
    'Authorization': `Bearer ${jwtToken}`
  }
})
  .then(response => response.json())
  .then(data => console.log(data));
```

### **curl**
```bash
# Get system status (no auth required)
curl http://localhost:8080/api/status

# Set temperature to 25°C (auth required) — Bearer token
curl -X POST "http://localhost:8080/api/set_setpoint" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGci..." \
  -d '{"setpoint_tenths": 250, "deadband_tenths": 10}'

# Get system configuration (no auth required)
curl http://localhost:8080/api/config

# Get telemetry data (auth required)
curl -H "Authorization: Bearer eyJhbGci..." \
  "http://localhost:8080/api/telemetry?limit=50"

# Health check (no auth required)
curl http://localhost:8080/api/health
```

> **🔐 Authentication Examples**: For authentication curl examples (login, logout, protected endpoints), see [Authentication Testing](../auth/10-testing.md).
