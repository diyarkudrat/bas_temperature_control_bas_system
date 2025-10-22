# API Overview

## 🌐 Base URL & Authentication

### **Base URL**
```
http://localhost:8080/
```
### **API Versioning**

- Preferred: `/api/v2/*` (stable)
- Deprecated: `/api/v1/*` (responses include `Deprecation: true` and `Sunset` headers)

Clients SHOULD migrate to `/api/v2/*`. Responses include `API-Version: 1|2`.

**Example**: `http://localhost:8080/`

> **Note**: This API runs on the computer-based server, not on the Pico W device. The Pico W connects to this server via WiFi.

### **Authentication**

> **🔐 Authentication Documentation**: For complete authentication system documentation, see:
> - **[Authentication Overview](../auth/01-overview.md)** - System overview and architecture
> - **[Authentication Flow](../auth/02-authentication-flow.md)** - Step-by-step authentication process
> - **[API Endpoints](../auth/06-api-endpoints.md)** - Authentication and protected endpoints
> - **[User Roles](../auth/07-user-roles.md)** - Role hierarchy and permission checking

**Authentication Status**: Authentication system is implemented and can be configured as:
- **Disabled**: No authentication required (development mode)
- **Shadow**: Log authentication attempts but don't block (testing mode)  
- **Enabled**: Full authentication required (production mode)

**Default Configuration**: Authentication is **enabled** in production. Some endpoints require authentication while others are public.

See [Configuration](../auth/05-configuration.md) for details on authentication modes.

---

## 📊 System Status APIs

### **GET /api/status**
Get current system status

**HTTP Method:** `GET`  
**Endpoint Path:** `/api/status`  
**Authentication:** Not required (public endpoint)

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
