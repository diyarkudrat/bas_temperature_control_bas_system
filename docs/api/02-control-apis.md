# Control APIs

## ⚙️ Control APIs

### **POST /api/set_setpoint**
Update temperature setpoint and deadband

**HTTP Method:** `POST`  
**Endpoint Path:** `/api/set_setpoint`  
**Authentication:** Required (operator or admin role)

**Query Parameters:** None

**Request Headers:**
- `Content-Type: application/json` (required)
- `X-Session-ID: your_session_token` (required for authentication)

**Request Body:**
```json
{
  "setpoint_tenths": 250,
  "deadband_tenths": 10
}
```

**Request Fields:**
- `setpoint_tenths` (integer, optional): Setpoint in tenths of °C (250 = 25.0°C)
- `deadband_tenths` (integer, optional): Deadband in tenths of °C (10 = 1.0°C)

**Example Request:**
```bash
curl -X POST "http://localhost:8080/api/set_setpoint" \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: sess_your_session_token_here" \
  -d '{
    "setpoint_tenths": 250,
    "deadband_tenths": 10
  }'
```

**Success Response (200):**
```json
{
  "success": true,
  "setpoint_tenths": 250,
  "deadband_tenths": 10
}
```

**Error Response (400):**
```json
{
  "error": "Invalid setpoint"
}
```

**Response Fields:**
- `success` (boolean): True if operation succeeded
- `setpoint_tenths` (integer): Current setpoint value
- `deadband_tenths` (integer): Current deadband value
- `error` (string, error only): Error message

### **POST /api/sensor_data**
Internal endpoint for Pico W client to send sensor readings

**HTTP Method:** `POST`  
**Endpoint Path:** `/api/sensor_data`  
**Authentication:** Not required (internal Pico W endpoint)

**Request Headers:**
- `Content-Type: application/json` (required)

**Request Body:**
```json
{
  "temp_tenths": 235,
  "sensor_ok": true,
  "timestamp": 1700000000000
}
```

**Response:**
```json
{
  "cool_active": false,
  "heat_active": true,
  "setpoint_tenths": 230,
  "deadband_tenths": 10
}
```

> **Note**: This endpoint is used internally by the Pico W client and returns control commands.

### **GET /api/health**
Health check endpoint

**HTTP Method:** `GET`  
**Endpoint Path:** `/api/health`  
**Authentication:** Not required (public health check)

**Example Request:**
```bash
curl "http://localhost:8080/api/health"
```

**Example Response:**
```json
{
  "status": "healthy",
  "timestamp": 1700000000
}
```
