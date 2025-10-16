# Data Model

## Collections

### telemetry
- Purpose: Append-only device measurements and controller state.
- Path: `telemetry`
- ID: Auto-ID
- Index: Composite `(tenant_id asc, device_id asc, timestamp_ms desc)`
- TTL: `timestamp_ms`

Example:
```json
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
```

### users
- Purpose: Human operators/admins, credentials, roles.
- Path: `users`
- ID: `user_id` (UUIDv4)

Example:
```json
{
  "user_id": "2c7c0f3a-2b07-4d6f-9a61-5c9b7b3f1c9e",
  "username": "operator1",
  "password_hash": "<hash>",
  "salt": "<salt>",
  "role": "operator",
  "created_at": 1734390000000,
  "last_login": 1734397200000,
  "failed_attempts": 0,
  "locked_until": 0,
  "password_history": []
}
```

### sessions
- Purpose: Short-lived sessions for authorization and expiry.
- Path: `sessions`
- ID: `session_id` (opaque)

Example:
```json
{
  "session_id": "sess_5d2e...",
  "user_id": "2c7c0f3a-...",
  "username": "operator1",
  "role": "operator",
  "created_at": 1734397200000,
  "expires_at": 1734400800000,
  "last_access": 1734399000000,
  "fingerprint": "fp_abcd",
  "ip_address": "203.0.113.10",
  "user_agent": "Mozilla/5.0 (...)"
}
```

### audit_log
- Purpose: Append-only audit events.
- Path: `audit_log`
- ID: Auto-ID
- TTL: `timestamp_ms`

Example:
```json
{
  "timestamp_ms": 1734398000000,
  "utc_timestamp": "2025-12-17T05:06:40.000Z",
  "user_id": "2c7c0f3a-...",
  "username": "operator1",
  "event_type": "LOGIN_SUCCESS",
  "ip_address": "203.0.113.10",
  "user_agent": "Mozilla/5.0 (...)",
  "details": {"method": "password"},
  "tenant_id": "t_123"
}
```

### devices
- Purpose: Device registry and metadata.
- Path: `devices`
- ID: `${tenant_id}_${device_id}` (preferred) or auto-ID

Example:
```json
{
  "tenant_id": "t_123",
  "device_id": "device_abc",
  "metadata": {
    "location": "Lab-1",
    "model": "Pico-2025",
    "notes": "Installed near intake"
  },
  "created_at": 1734390000000,
  "last_seen": 1734398405000,
  "status": "active"
}
```
