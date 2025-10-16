# API ↔ Database Mapping

This document links major API endpoints to DAL repositories and query shapes, with concrete request/response examples.

## Telemetry

### GET /api/telemetry (recent N by device)
- Repo: `TelemetryRepository.query_recent_for_device()`
- Index: `(tenant_id, device_id, timestamp_ms desc)`
- Pagination: `start_after` doc ID → `next_offset`

Request:
```bash
curl "http://localhost:8080/api/telemetry?device_id=device_abc&limit=3" \
  -H "X-Session-ID: sess_your_token" \
  -H "X-BAS-Tenant: t_123"
```

Response (200):
```json
[
  {
    "tenant_id": "t_123",
    "device_id": "device_abc",
    "timestamp_ms": 1734398405123,
    "utc_timestamp": "2025-12-17T05:20:05.123Z",
    "temp_tenths": 237,
    "setpoint_tenths": 230,
    "deadband_tenths": 10,
    "cool_active": false,
    "heat_active": true,
    "state": "HEATING",
    "sensor_ok": true
  },
  {
    "tenant_id": "t_123",
    "device_id": "device_abc",
    "timestamp_ms": 1734398403123,
    "utc_timestamp": "2025-12-17T05:20:03.123Z",
    "temp_tenths": 236,
    "setpoint_tenths": 230,
    "deadband_tenths": 10,
    "cool_active": false,
    "heat_active": true,
    "state": "HEATING",
    "sensor_ok": true
  }
]
```

### GET /api/telemetry/window (time range)
- Repo: `TelemetryRepository.query_time_window()`

Request:
```bash
curl "http://localhost:8080/api/telemetry/window?device_id=device_abc&start=1734398000000&end=1734398600000&limit=1000" \
  -H "X-Session-ID: sess_your_token" \
  -H "X-BAS-Tenant: t_123"
```

Response (200): same record shape as above array.

### GET /api/telemetry/paginated (recent with cursor)
- Repo: `TelemetryRepository.query_recent_paginated()`

Request:
```bash
curl "http://localhost:8080/api/telemetry/paginated?device_id=device_abc&limit=100&start_after=doc_123" \
  -H "X-Session-ID: sess_your_token" \
  -H "X-BAS-Tenant: t_123"
```

Response (200):
```json
{
  "data": [
    {
      "tenant_id": "t_123",
      "device_id": "device_abc",
      "timestamp_ms": 1734398405123,
      "utc_timestamp": "2025-12-17T05:20:05.123Z",
      "temp_tenths": 237,
      "setpoint_tenths": 230,
      "deadband_tenths": 10,
      "cool_active": false,
      "heat_active": true,
      "state": "HEATING",
      "sensor_ok": true
    }
  ],
  "last_doc_id": "doc_456",
  "has_more": true
}
```

## Users & Sessions

### POST /auth/login
- Repo: `UsersRepository.get_by_username()` → verify password; on success `SessionsStore.create_session()`; audit success/failure

Request:
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -H "X-BAS-Tenant: t_123" \
  -d '{"username":"admin","password":"Admin123!@#X"}'
```

Response (200 success):
```json
{
  "status": "success",
  "session_id": "sess_abc123",
  "expires_in": 1800,
  "user": {
    "user_id": "2c7c0f3a-2b07-4d6f-9a61-5c9b7b3f1c9e",
    "username": "admin",
    "role": "admin",
    "last_login": 1734399000000
  }
}
```

Response (401 failure):
```json
{
  "error": "Invalid credentials",
  "code": "INVALID_CREDENTIALS"
}
```

### POST /auth/logout
- Repo: `SessionsStore.invalidate_session()`; audit session destruction

Request:
```bash
curl -X POST http://localhost:8080/auth/logout \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: sess_abc123" \
  -H "X-BAS-Tenant: t_123" \
  -d '{}'
```

Response (200):
```json
{
  "status": "success",
  "message": "Logged out successfully"
}
```

### GET /auth/status
- Repo: `SessionsStore.get_session()` → validate expiry and fingerprint

Request:
```bash
curl http://localhost:8080/auth/status \
  -H "X-Session-ID: sess_abc123" \
  -H "X-BAS-Tenant: t_123"
```

Response (200 valid):
```json
{
  "status": "valid",
  "user": {
    "user_id": "2c7c0f3a-2b07-4d6f-9a61-5c9b7b3f1c9e",
    "username": "admin",
    "role": "admin",
    "login_time": 1734398800000
  },
  "expires_in": 1200
}
```

Response (401 expired):
```json
{
  "error": "Session expired",
  "code": "SESSION_EXPIRED"
}
```

## Audit

### GET /api/audit/recent?limit=100
- Repo: `AuditLogStore.query_recent_events()`

Request:
```bash
curl "http://localhost:8080/api/audit/recent?limit=50" \
  -H "X-Session-ID: sess_abc123" \
  -H "X-BAS-Tenant: t_123"
```

Response (200):
```json
[
  {
    "timestamp_ms": 1734398000000,
    "utc_timestamp": "2025-12-17T05:06:40.000Z",
    "event_type": "LOGIN_SUCCESS",
    "user_id": "2c7c0f3a-...",
    "username": "admin",
    "ip_address": "203.0.113.10",
    "user_agent": "Mozilla/5.0 (...)",
    "details": {"method": "password", "session_id": "sess_abc123"},
    "tenant_id": "t_123"
  }
]
```

## Devices

### POST /api/devices/register
- Repo: `DevicesStore.register_device()`

Request:
```bash
curl -X POST http://localhost:8080/api/devices/register \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: sess_abc123" \
  -H "X-BAS-Tenant: t_123" \
  -d '{"device_id": "device_abc", "metadata": {"location": "Lab-1"}}'
```

Response (200):
```json
{
  "success": true,
  "device": {
    "tenant_id": "t_123",
    "device_id": "device_abc",
    "metadata": {"location": "Lab-1"},
    "created_at": 1734390000000,
    "last_seen": 1734390000000,
    "status": "active",
    "id": "t_123_device_abc"
  }
}
```

### GET /api/devices
- Repo: `DevicesStore.list_devices_for_tenant()`

Request:
```bash
curl http://localhost:8080/api/devices \
  -H "X-Session-ID: sess_abc123" \
  -H "X-BAS-Tenant: t_123"
```

Response (200):
```json
[
  {
    "id": "t_123_device_abc",
    "tenant_id": "t_123",
    "device_id": "device_abc",
    "metadata": {"location": "Lab-1"},
    "created_at": 1734390000000,
    "last_seen": 1734398405000,
    "status": "active"
  }
]
```

## Tenancy Enforcement

- Middleware: Require `TENANT_ID_HEADER` (default `X-BAS-Tenant`), bind session tenant at login
- DAL: Reject cross-tenant reads/writes via repository mixins; audit violations
