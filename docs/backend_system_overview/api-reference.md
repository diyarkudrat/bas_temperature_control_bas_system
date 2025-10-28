# API Reference

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard with telemetry graphs |
| `/status` | GET | System status (JSON) |
| `/set?token=xxx` | POST | Update setpoint |
| `/events` | GET | Live updates (SSE) |
| `/config` | GET | Configuration |
| `/logs?token=xxx` | GET | System logs |
| `/telemetry` | GET | Time-series data for graphing |
| `/telemetry/stats` | GET | Aggregated statistics |
| `/telemetry/health` | GET | Telemetry system health |

### Example: Update Setpoint
```bash
curl -X POST "http://<pico-ip>/set?token=testapitoken" \
  -H "Content-Type: application/json" \
  -d '{"sp": 250, "db": 10}'
```
