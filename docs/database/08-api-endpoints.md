# API ↔ Database Mapping

This document links current API endpoints to DAL repositories and query shapes, with concrete request/response examples. Endpoints not present in the Flask app are omitted.

## Telemetry

### GET /api/telemetry (recent N)
- Repo: `TelemetryRepository.query_recent_for_device()`
- Auth: read-only+ (Bearer JWT preferred; session fallback optional)
- Index: `(tenant_id, device_id, timestamp_ms desc)`

Request:
```bash
curl "http://localhost:8080/api/telemetry?limit=3" \
  -H "Authorization: Bearer eyJhbGci..." \
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

Note: The Flask API currently exposes a single `/api/telemetry` endpoint. Time-window and paginated variants are available at the repository layer for internal use.

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
  "expires_in": 1800,
  "user": {
    "username": "admin",
    "role": "admin"
  }
}
```
Note: Session ID is set as HttpOnly cookie `bas_session_id`.

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

There is no public audit API in the Flask app. Internally, `AuditLogStore` writes to the `audit_log` collection (see repository docs). Dashboards may use service-level access instead of public endpoints.

## Devices

There are no public device endpoints in the Flask app. Devices are managed via `DevicesStore` at the service layer.

## Tenancy Enforcement

- Middleware: Prefer session-bound tenant when present; otherwise honor header `X-BAS-Tenant`
- DAL: Reject cross-tenant writes/reads via repository mixins; audit violations
