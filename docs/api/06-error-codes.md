# Error Codes

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
