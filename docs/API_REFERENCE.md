# BAS System API Reference

**Complete API documentation for the Building Automation System (BAS) temperature controller.**

---

## 📋 Table of Contents

- [🌐 Base URL & Authentication](#-base-url--authentication)
- [📊 System Status APIs](#-system-status-apis)
- [⚙️ Control APIs](#️-control-apis)
- [📋 Configuration APIs](#-configuration-apis)
- [📈 Telemetry APIs](#-telemetry-apis)
- [🌐 Web Dashboard](#-web-dashboard)
- [📊 Error Codes](#-error-codes)
- [📱 Client Examples](#-client-examples)

---

## 🌐 Base URL & Authentication

### **Base URL**
```
http://localhost:8080/
```

**Example**: `http://localhost:8080/`

> **Note**: This API runs on the computer-based server, not on the Pico W device. The Pico W connects to this server via WiFi.

### **Authentication Methods**

**Current Implementation**: No authentication required. All endpoints are publicly accessible.

---

## 📊 System Status APIs

### **GET /api/status**
Get current system status

**HTTP Method:** `GET`  
**Endpoint Path:** `/api/status`  
**Authentication:** Not required

**Query Parameters:** None

**Request Headers:** None required

**Example Request:**
```bash
curl "http://localhost:8080/api/status"
```

**Example Response:**
```json
{
  "temp_tenths": 235,
  "setpoint_tenths": 250,
  "deadband_tenths": 10,
  "state": "IDLE",
  "cool_active": false,
  "heat_active": true,
  "sensor_ok": true,
  "timestamp": 1700000000000
}
```

**Response Fields:**
- `temp_tenths` (integer): Current temperature in tenths of °C (235 = 23.5°C)
- `setpoint_tenths` (integer): Target temperature in tenths of °C
- `deadband_tenths` (integer): Temperature buffer in tenths of °C
- `state` (string): Controller state (IDLE, COOLING, HEATING, FAULT)
- `cool_active` (boolean): Cooling relay status
- `heat_active` (boolean): Heating relay status
- `sensor_ok` (boolean): Temperature sensor health
- `timestamp` (integer): Unix timestamp in milliseconds

---

## ⚙️ Control APIs

### **POST /api/set_setpoint**
Update temperature setpoint and deadband

**HTTP Method:** `POST`  
**Endpoint Path:** `/api/set_setpoint`  
**Authentication:** Not required

**Query Parameters:** None

**Request Headers:**
- `Content-Type: application/json` (required)

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
**Authentication:** Not required

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
**Authentication:** Not required

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

---

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


---

## 📈 Telemetry Endpoints

### **GET /api/telemetry**
Get time-series telemetry data

**Parameters:**
- `limit` (integer): Maximum number of points (default: 100)

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


---


---


---

## 🌐 Web Dashboard

### **GET /**
Web dashboard with real-time graphs and controls

**Features:**
- Real-time temperature graph
- Controller status display
- Setpoint adjustment controls
- System health indicators
- Telemetry visualization

**Access:** Open `http://localhost:8080/` in your browser

---


---

## 📊 Error Codes

| HTTP Code | Description | Action |
|-----------|-------------|--------|
| 400 | Bad Request | Check request format and parameters |
| 500 | Internal Server Error | Check server logs for details |

### Common Error Messages
- `"Invalid setpoint"`: Setpoint value is outside valid range (100-400 tenths)
- `"Invalid deadband"`: Deadband value is outside valid range (0-50 tenths)
- `"No data received"`: POST request body is empty or invalid JSON
- `"Internal server error"`: Server-side processing error

---


---

## 📱 Client Examples

### **Python**
```python
import requests

# Get status
response = requests.get('http://localhost:8080/api/status')
status = response.json()

# Set temperature
response = requests.post(
    'http://localhost:8080/api/set_setpoint',
    json={'setpoint_tenths': 250, 'deadband_tenths': 10}
)

# Get telemetry data
response = requests.get('http://localhost:8080/api/telemetry?limit=50')
telemetry = response.json()
```

### **JavaScript**
```javascript
// Get system status
fetch('http://localhost:8080/api/status')
  .then(response => response.json())
  .then(data => console.log(data));

// Set temperature
fetch('http://localhost:8080/api/set_setpoint', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    setpoint_tenths: 250,
    deadband_tenths: 10
  })
});

// Get telemetry data
fetch('http://localhost:8080/api/telemetry?limit=50')
  .then(response => response.json())
  .then(data => console.log(data));
```

### **curl**
```bash
# Get system status
curl http://localhost:8080/api/status

# Set temperature to 25°C
curl -X POST "http://localhost:8080/api/set_setpoint" \
  -H "Content-Type: application/json" \
  -d '{"setpoint_tenths": 250, "deadband_tenths": 10}'

# Get system configuration
curl http://localhost:8080/api/config

# Get telemetry data
curl "http://localhost:8080/api/telemetry?limit=50"

# Health check
curl http://localhost:8080/api/health
```

---

This API reference provides complete documentation for all BAS system endpoints, including status monitoring, control, telemetry, and configuration.
