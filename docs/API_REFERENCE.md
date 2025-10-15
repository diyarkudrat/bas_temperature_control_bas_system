# BAS System API Reference

**Complete API documentation for the Building Automation System (BAS) temperature controller.**

---

## 📋 Table of Contents

- [🌐 Base URL & Authentication](#-base-url--authentication)
- [📊 System Status APIs](#-system-status-apis)
- [⚙️ Control APIs](#️-control-apis)
- [📋 Configuration APIs](#-configuration-apis)
- [📈 Telemetry APIs](#-telemetry-apis)
- [🔄 Real-time Updates](#-real-time-updates)
- [📝 Logging APIs](#-logging-apis)
- [🌐 Web Dashboard](#-web-dashboard)
- [🔐 Authentication APIs (Coming Soon)](#-authentication-apis-coming-soon)
- [📊 Error Codes](#-error-codes)
- [🔧 Rate Limiting](#-rate-limiting)
- [📱 Client Examples](#-client-examples)

---

## 🌐 Base URL & Authentication

### **Base URL**
```
http://<pico-ip-address>/
```

**Example**: `http://192.168.1.129/`

### **Authentication Methods**

#### Current System (Token-based)
```bash
# Add token as query parameter
curl "http://192.168.1.129/status?token=your-api-token"
```

#### Enhanced System (Session-based) - Coming Soon
```bash
# Use session header
curl -H "X-Session-ID: sess_abc123def456" "http://192.168.1.129/status"
```

---

## 📊 System Status APIs

### **GET /status**
Get current system status

**HTTP Method:** `GET`  
**Endpoint Path:** `/status`  
**Authentication:** Not required

**Query Parameters:** None

**Request Headers:** None required

**Example Request:**
```bash
curl "http://192.168.1.129/status"
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
  "alarm": false,
  "error_code": 0,
  "timestamp": 1700000000
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
- `alarm` (boolean): System alarm status
- `error_code` (integer): Error code (0 = no error)
- `timestamp` (integer): Unix timestamp in milliseconds

---

## ⚙️ Control APIs

### **POST /set**
Update temperature setpoint and deadband

**HTTP Method:** `POST`  
**Endpoint Path:** `/set`  
**Authentication:** Required (token or session)

**Query Parameters:**
- `token` (string, required): API authentication token

**Request Headers:**
- `Content-Type: application/json` (required)

**Request Body:**
```json
{
  "sp": 250,
  "db": 10
}
```

**Request Fields:**
- `sp` (integer, required): Setpoint in tenths of °C (250 = 25.0°C)
- `db` (integer, optional): Deadband in tenths of °C (10 = 1.0°C)

**Example Request:**
```bash
curl -X POST "http://192.168.1.129/set?token=your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "sp": 250,
    "db": 10
  }'
```

**Success Response (200):**
```json
{
  "status": "success",
  "updated": {
    "setpoint_tenths": 250,
    "deadband_tenths": 10
  },
  "timestamp": 1700000000
}
```

**Error Response (400):**
```json
{
  "error": "Invalid parameters",
  "code": "INVALID_REQUEST",
  "details": {
    "message": "Setpoint must be between 100 and 400 (10.0°C to 40.0°C)"
  }
}
```

**Response Fields:**
- `status` (string): "success" or "error"
- `updated` (object): Updated configuration values
  - `setpoint_tenths` (integer): New setpoint value
  - `deadband_tenths` (integer): New deadband value
- `timestamp` (integer): Unix timestamp in milliseconds
- `error` (string, error only): Error message
- `code` (string, error only): Error code
- `details` (object, error only): Additional error information

---

## 📋 Configuration APIs

### **GET /config**
Get current system configuration

**HTTP Method:** `GET`  
**Endpoint Path:** `/config`  
**Authentication:** Not required

**Query Parameters:** None

**Request Headers:** None required

**Example Request:**
```bash
curl "http://192.168.1.129/config"
```

**Example Response:**
```json
{
  "current_profile": "default",
  "profiles": {
    "default": {
      "setpoint_tenths": 230,
      "deadband_tenths": 5,
      "sample_period_ms": 2000,
      "min_on_ms": 10000,
      "min_off_ms": 10000,
      "pin_ds18b20": 4,
      "pin_relay_cool": 15,
      "pin_relay_heat": 14,
      "relay_active_high": true,
      "cool_only": true,
      "heat_always_on": true
    }
  },
  "hardware": {
    "sensor_type": "DS18B20",
    "display_type": "SSD1306",
    "network_status": "connected"
  }
}
```

**Response Fields:**
- `current_profile` (string): Active configuration profile name
- `profiles` (object): Available configuration profiles
  - `[profile_name]` (object): Profile configuration
    - `setpoint_tenths` (integer): Default setpoint in tenths of °C
    - `deadband_tenths` (integer): Default deadband in tenths of °C
    - `sample_period_ms` (integer): Control loop period in milliseconds
    - `min_on_ms` (integer): Minimum actuator on time
    - `min_off_ms` (integer): Minimum actuator off time
    - `pin_ds18b20` (integer): DS18B20 sensor GPIO pin
    - `pin_relay_cool` (integer): Cooling relay GPIO pin
    - `pin_relay_heat` (integer): Heating relay GPIO pin
    - `relay_active_high` (boolean): Relay activation logic
    - `cool_only` (boolean): Cooling-only mode
    - `heat_always_on` (boolean): Heating always on mode
- `hardware` (object): Hardware information
  - `sensor_type` (string): Temperature sensor type
  - `display_type` (string): Display type
  - `network_status` (string): Network connection status

### **POST /set_profile**
Switch configuration profile

**HTTP Method:** `POST`  
**Endpoint Path:** `/set_profile`  
**Authentication:** Required (token or session)

**Query Parameters:**
- `token` (string, required): API authentication token

**Request Headers:**
- `Content-Type: application/json` (required)

**Request Body:**
```json
{
  "profile": "production"
}
```

**Request Fields:**
- `profile` (string, required): Profile name to switch to

**Example Request:**
```bash
curl -X POST "http://192.168.1.129/set_profile?token=your-token" \
  -H "Content-Type: application/json" \
  -d '{"profile": "production"}'
```

**Success Response (200):**
```json
{
  "status": "success",
  "active_profile": "production",
  "message": "Profile switched successfully"
}
```

**Error Response (400):**
```json
{
  "error": "Profile not found",
  "code": "PROFILE_NOT_FOUND",
  "details": {
    "available_profiles": ["default", "debug"]
  }
}
```

**Response Fields:**
- `status` (string): "success" or "error"
- `active_profile` (string): Currently active profile name
- `message` (string): Success message
- `error` (string, error only): Error message
- `code` (string, error only): Error code
- `details` (object, error only): Additional error information

---

## 📈 Telemetry Endpoints

### **GET /telemetry**
Get time-series telemetry data

**Parameters:**
- `duration_ms` (integer): Time range in milliseconds (default: 600000 = 10 minutes)
- `limit` (integer): Maximum number of points (default: 300)
- `fields` (string): Comma-separated field list (default: all)

**Example:**
```bash
curl "http://192.168.1.129/telemetry?duration_ms=3600000&limit=100&fields=temp_tenths,state"
```

**Response:**
```json
{
  "points": [
    {
      "timestamp_ms": 1700000000,
      "temp_tenths": 235,
      "setpoint_tenths": 250,
      "state": "IDLE",
      "cool_active": false,
      "heat_active": true,
      "alarm": false
    }
  ],
  "metadata": {
    "total_points": 100,
    "duration_ms": 3600000,
    "start_time_ms": 1699996400,
    "end_time_ms": 1700000000
  }
}
```

### **GET /telemetry/stats**
Get aggregated telemetry statistics

**Parameters:**
- `duration_ms` (integer): Time range in milliseconds (default: 3600000 = 1 hour)

**Response:**
```json
{
  "temperature": {
    "current": 23.5,
    "average": 23.2,
    "min": 22.8,
    "max": 24.1,
    "std_dev": 0.3
  },
  "actuators": {
    "cooling_cycles": 12,
    "total_cooling_time_ms": 180000,
    "average_cycle_duration_ms": 15000,
    "heating_uptime_percent": 95.5
  },
  "system": {
    "uptime_ms": 86400000,
    "alarm_count": 0,
    "error_count": 0,
    "data_points": 43200
  }
}
```

### **GET /telemetry/health**
Get telemetry system health status

**Response:**
```json
{
  "status": "healthy",
  "buffer_utilization": 45.2,
  "points_collected": 1000,
  "export_success_rate": 98.5,
  "last_export_ms": 1700000000,
  "backends": [
    {
      "name": "CSV",
      "status": "active",
      "export_count": 150,
      "error_count": 2
    }
  ]
}
```

---

## 🔄 Real-time Updates

### **GET /events**
Server-Sent Events (SSE) for real-time updates

**Usage:**
```javascript
const eventSource = new EventSource('http://192.168.1.129/events');
eventSource.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('Update:', data);
};
```

**Event Types:**
- `status_update`: Controller status changes
- `temperature_change`: Temperature readings
- `state_transition`: Controller state changes
- `alarm`: System alarms
- `error`: System errors

**Event Format:**
```json
{
  "type": "status_update",
  "timestamp": 1700000000,
  "data": {
    "temp_tenths": 235,
    "state": "COOLING",
    "cool_active": true
  }
}
```

---

## 📝 Logging Endpoints

### **GET /logs**
Get system logs

**Authentication:** Required

**Parameters:**
- `level` (string): Log level filter (debug, info, warning, error)
- `component` (string): Component filter
- `limit` (integer): Maximum number of entries (default: 50)

**Example:**
```bash
curl "http://192.168.1.129/logs?token=your-token&level=error&limit=20"
```

**Response:**
```json
{
  "logs": [
    {
      "timestamp_ms": 1700000000,
      "level": "error",
      "component": "Controller",
      "message": "Sensor read failed",
      "data": {
        "error_code": 102,
        "retry_count": 3
      }
    }
  ],
  "metadata": {
    "total_entries": 20,
    "filtered_by": {
      "level": "error",
      "limit": 20
    }
  }
}
```

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

**Access:** Open `http://<pico-ip>/` in your browser

---

## 🔐 Authentication Endpoints (Coming Soon)

### **POST /auth/login**
Authenticate with username/password

**Request:**
```json
{
  "username": "operator1",
  "password": "user_password",
  "phone_number": "+1234567890"
}
```

**Response:**
```json
{
  "status": "mfa_required",
  "message": "MFA code sent to your phone",
  "expires_in": 300
}
```

### **POST /auth/verify**
Verify MFA code

**Request:**
```json
{
  "username": "operator1",
  "code": "123456"
}
```

**Response:**
```json
{
  "status": "success",
  "session_id": "sess_abc123def456",
  "expires_in": 1800,
  "user": {
    "username": "operator1",
    "role": "operator"
  }
}
```

### **POST /auth/logout**
Terminate session

**Request:**
```json
{
  "session_id": "sess_abc123def456"
}
```

### **GET /auth/status**
Check session validity

**Headers:**
```
X-Session-ID: sess_abc123def456
```

---

## 📊 Error Codes

| Code | Description | Action |
|------|-------------|--------|
| 0 | No error | - |
| 101 | Sensor not found | Check DS18B20 wiring |
| 102 | Sensor read failed | Check sensor connection |
| 201 | Actuator init failed | Check relay wiring |
| 301 | Controller invalid state | System restart required |
| 401 | Network connection failed | Check WiFi credentials |
| 501 | System out of memory | Reduce telemetry buffer size |
| 601 | Display init failed | Check I2C wiring |

---

## 🔧 Rate Limiting

- **General API**: 100 requests/minute per IP
- **Authentication**: 5 attempts per 15 minutes per IP
- **SSE Connections**: 3 maximum concurrent
- **Request Size**: 8KB maximum
- **Connection Timeout**: 30 seconds

---

## 📱 Client Examples

### **Python**
```python
import requests

# Get status
response = requests.get('http://192.168.1.129/status')
status = response.json()

# Set temperature
response = requests.post(
    'http://192.168.1.129/set?token=your-token',
    json={'sp': 250, 'db': 10}
)
```

### **JavaScript**
```javascript
// Get telemetry data
fetch('http://192.168.1.129/telemetry?duration_ms=3600000')
  .then(response => response.json())
  .then(data => console.log(data));

// Real-time updates
const eventSource = new EventSource('http://192.168.1.129/events');
eventSource.onmessage = event => {
  const data = JSON.parse(event.data);
  updateDisplay(data);
};
```

### **curl**
```bash
# Get system status
curl http://192.168.1.129/status

# Set temperature to 25°C
curl -X POST "http://192.168.1.129/set?token=your-token" \
  -H "Content-Type: application/json" \
  -d '{"sp": 250, "db": 10}'

# Get telemetry for last hour
curl "http://192.168.1.129/telemetry?duration_ms=3600000"
```

---

This API reference provides complete documentation for all BAS system endpoints, including authentication, control, telemetry, and real-time updates.
