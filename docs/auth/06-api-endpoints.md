# API Endpoints

## 🚀 API Endpoints Explained

### Authentication Endpoints

#### `POST /auth/login`
**Purpose**: User login with username/password

**Request**:
```json
{
    "username": "john_operator",
    "password": "SecurePass123!"
}
```

**Success Response**:
```json
{
    "status": "success",
    "expires_in": 1800,
    "user": {
        "username": "john_operator",
        "role": "operator"
    }
}
```
*Also sets an HttpOnly cookie with the session token*

#### `POST /auth/logout`
**Purpose**: End user session

**Request**: Session token in cookie or `X-Session-ID` header

**Response**:
```json
{
    "status": "success",
    "message": "Logged out successfully"
}
```

#### `GET /auth/status`
**Purpose**: Check if session is still valid

**Request**: Session token in cookie or `X-Session-ID` header

**Response** (if valid):
```json
{
    "status": "valid",
    "user": {
        "username": "john_operator",
        "role": "operator",
        "login_time": 1700000000
    },
    "expires_in": 1200
}
```

### Protected Endpoints

#### `POST /set` (Temperature Control)
**Purpose**: Change temperature setpoint (requires operator+ role)

**Headers**:
```
X-Session-ID: sess_abc123def456...
Content-Type: application/json
```

**Request**:
```json
{
    "sp": 250,    // Setpoint in tenths of degrees (25.0°C)
    "db": 10      // Deadband in tenths (1.0°C)
}
```

**Response**:
```json
{
    "status": "success",
    "updated": {
        "setpoint_tenths": 250,
        "deadband_tenths": 10
    },
    "updated_by": "john_operator",
    "timestamp": 1700000000
}
```
