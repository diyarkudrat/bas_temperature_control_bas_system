# Telemetry APIs

## 📈 Telemetry Endpoints

### **GET /api/telemetry**
Get time-series telemetry data

**Authentication:** Required (read-only or higher)

**Parameters:**
- `limit` (integer): Maximum number of points (default: 100)
- `device_id` (string): Device identifier (optional; defaults to `unknown`)

**Example:**
```bash
curl "http://localhost:8080/api/telemetry?limit=50"
```

**Response:**
```json
[
  {
    "timestamp": 1700000000000,
    "temp_tenths": 235,
    "setpoint_tenths": 250,
    "deadband_tenths": 10,
    "cool_active": false,
    "heat_active": true,
    "state": "IDLE",
    "sensor_ok": true
  }
]
```
