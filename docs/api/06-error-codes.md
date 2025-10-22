# Error Codes

## 📊 Error Codes

| Code | HTTP | Meaning |
|------|------|---------|
| MISSING_FIELDS | 400 | Required fields are missing |
| INVALID_ARGUMENT | 400 | Argument value/type invalid |
| VALIDATION_ERROR | 400 | Domain validation failed |
| NOT_FOUND | 404 | Resource not found |
| PERMISSION_DENIED | 403 | Operation not permitted |
| AUTH_ERROR | 401 | Authentication/authorization failed |
| FIRESTORE_ERROR | 502 | Upstream Firestore error |
| DB_ERROR | 500 | Internal DB error |
| INTERNAL_ERROR | 500 | Unhandled server error |

All error responses follow:

```json
{ "error": "message", "code": "SNAKE_CASE", "version": "v1|v2" }
```

### Common Error Messages
- "Invalid setpoint": Setpoint outside valid range (100-400 tenths)
- "Invalid deadband": Deadband outside valid range (0-50 tenths)
- "No data received": POST body empty or invalid JSON
- "Internal server error": Unhandled server-side error
