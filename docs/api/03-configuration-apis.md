# Configuration APIs

## 📋 Configuration APIs

### **GET /api/config**
Get current system configuration

**HTTP Method:** `GET`  
**Endpoint Path:** `/api/config`  
**Authentication:** Not required

**Query Parameters:** None

**Request Headers:** None required

**Example Request:**
```bash
curl "http://localhost:8080/api/config"
```

**Example Response:**
```json
{
  "setpoint_tenths": 230,
  "deadband_tenths": 10,
  "min_on_time_ms": 10000,
  "min_off_time_ms": 10000
}
```

**Response Fields:**
- `setpoint_tenths` (integer): Current setpoint in tenths of °C
- `deadband_tenths` (integer): Current deadband in tenths of °C
- `min_on_time_ms` (integer): Minimum actuator on time in milliseconds
- `min_off_time_ms` (integer): Minimum actuator off time in milliseconds
