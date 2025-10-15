# BAS Temperature Controller

Production-grade temperature control system for Raspberry Pi Pico W with MicroPython.

Single-zone closed-loop controller with web API, OLED display, and clean architecture.

---

## 🚀 Quick Setup

### 1. Hardware Connections

| Component | GPIO | Notes |
|-----------|------|-------|
| DS18B20 Sensor | GP4 | 1-Wire + 4.7kΩ pull-up |
| Cooling Relay | GP15 | Active-HIGH |
| Heating Relay | GP14 | LEDs, always ON |
| OLED SDA | GP0 | I²C |
| OLED SCL | GP1 | I²C |

### 2. Configure WiFi

Edit `config/config.py`:
```python
WIFI_SSID = "YourNetwork"
WIFI_PASS = "YourPassword"
API_TOKEN = "your-token"       # For API security
DEFAULT_SETPOINT_C = 270       # 27.0°C (in tenths)
```

### 3. Deploy

```bash
./deploy              # Deploy to Pico
./monitor             # Watch it run
```

### 4. Access

**Web Dashboard:**
```
http://<pico-ip>/
```

**API:**
```bash
# Get status
curl http://<pico-ip>/status

# Set temperature to 25°C
curl -X POST "http://<pico-ip>/set?token=your-token" \
  -H "Content-Type: application/json" \
  -d '{"sp": 250}'
```

---

## 📐 Architecture

### Simple Overview

```
┌──────────────────────────────────────────────┐
│  main.py (SystemOrchestrator)                │
│  ┌──────────┐  ┌─────────┐  ┌────────────┐  │
│  │Controller│  │ Display │  │ API Server │  │
│  └──────────┘  └─────────┘  └────────────┘  │
└──────────────────────────────────────────────┘
         │              │              │
┌────────┴──────────────┴──────────────┴───────┐
│  interfaces/ (Sensor, Actuator, Clock)       │
└──────────────────────────────────────────────┘
         │              │              │
┌────────┴──────────────┴──────────────┴───────┐
│  core/ (DS18B20, Relay, SystemClock)         │
└──────────────────────────────────────────────┘
```

### Key Modules

- **main.py** - Entry point with cooperative scheduler
- **controller.py** - FSM with hysteresis & anti-short-cycle
- **display.py** - OLED with view model pattern
- **core/** - Hardware abstraction (relay, sensor, clock)
- **interfaces/** - Clean contracts for testability
- **services/** - Config, logging, error handling
- **netctrl/** - WiFi connection + HTTP API server

---

## 🔧 Configuration

All settings in `config/config.py`:

```python
# Temperature Control
DEFAULT_SETPOINT_C = 270      # Target temp (tenths °C)
DEADBAND_TENTHS_C = 5         # Hysteresis (0.5°C)
MIN_ON_MS = 10000             # Anti-short-cycle
MIN_OFF_MS = 10000

# Timing
SAMPLE_PERIOD_MS = 2000       # Control loop period

# Hardware
PIN_DS18B20 = 4
PIN_RELAY_COOL = 15
PIN_RELAY_HEAT = 14
RELAY_ACTIVE_HIGH = True

# Network
WIFI_SSID = "YourNetwork"
WIFI_PASS = "YourPassword"
API_TOKEN = "your-token"

# Debug
ENABLE_DEBUG_LOGS = True      # Show real-time status
```

---

## 🛠️ Development

### Deploy & Monitor
```bash
./deploy              # Deploy to Pico (auto-detects device)
./monitor             # Real-time output
./status              # Quick health check
scripts/repl.sh       # Interactive Python
```

### Testing
```bash
# On Pico (via REPL)
import tests.test_runner as t
t.main()

# From computer
python3 tools/test_api.py
```

### Debugging
```bash
scripts/wifi_debug.sh      # WiFi diagnostics
scripts/verify.sh          # Verify installation
```

---

## 🏗️ Extending the Project

### Add a New Sensor

1. Create interface implementation in `core/`:
```python
# core/my_sensor.py
from interfaces import TemperatureSensor, SensorReading

class MySensor(TemperatureSensor):
    def read(self):
        # Your implementation
        return SensorReading(...)
```

2. Use it in `main.py`:
```python
from core import MySensor
sensor = MySensor(pin=5)
```

### Add Multi-Zone Support

See `blueprints/multi_zone.py` for complete patterns:
- Zone Manager with scheduler
- Event bus for coordination
- Per-zone configuration

### Telemetry System

**Fully integrated production telemetry with extensibility!** See `TELEMETRY.md` for complete documentation.

Core Features:
- Ring buffer with 1000-point capacity (~33 minutes @ 2s interval)
- Real-time graphs with Chart.js
- Temperature history, actuator activity, statistics
- Optional CSV export for long-term analysis
- Memory-bounded, non-blocking design
- Performance metrics and state transition logging

**Extensibility Features:**
- **Custom collectors**: Add humidity, pressure, energy monitoring without modifying core
- **Multi-zone support**: Built-in zone_id for multiple control zones
- **Custom metrics**: Extensible `custom_data` dict for arbitrary telemetry
- **Non-intrusive**: Extend functionality without changing core code

See `EXTENSIBILITY_GUIDE.md` for practical extension patterns including:
- Adding additional sensors (humidity, pressure, light, outdoor temp)
- Multi-zone aggregation
- Energy/power monitoring
- MQTT integration for cloud monitoring
- Alarm systems with custom thresholds
- SD card storage for long-term data
- Occupancy detection integration

Access via web dashboard at `http://<pico-ip>/` or API:
```bash
# Get 10 minutes of telemetry data
curl http://<pico-ip>/telemetry?duration_ms=600000

# Get statistics for last hour
curl http://<pico-ip>/telemetry/stats?duration_ms=3600000

# Extension example: add custom humidity sensor
def collect_humidity():
    return {'humidity_pct': read_sensor()}
telemetry.register_custom_collector('humidity', collect_humidity)
```

---

## 📁 Project Structure

```
BAS System Project/
├── README.md              ← Start here
├── main.py                ← Entry point
├── controller.py          ← Control logic
├── display.py             ← OLED interface
├── boot.py                ← Hardware init
│
├── config/                ← System configuration
├── core/                  ← Hardware drivers
├── interfaces/            ← Abstract contracts
├── services/              ← Config, logging, errors
├── netctrl/               ← WiFi & API
│
├── scripts/               ← Deployment tools
├── tests/                 ← Test suite (40+ tests)
├── tools/                 ← Development utilities
└── blueprints/            ← Extension patterns
```

---

## 🌐 API Reference

### Endpoints

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
curl -X POST "http://192.168.1.129/set?token=testapitoken" \
  -H "Content-Type: application/json" \
  -d '{"sp": 250, "db": 10}'
```

Response:
```json
{"status": "success", "updated": {"setpoint_tenths": 250}}
```

---

## 🧪 Testing

```bash
# Run full test suite
scripts/repl.sh
>>> import tests.test_runner as t
>>> t.main()

# Test API from computer
python3 tools/test_api.py
```

---

## 🔒 Security

- Rate limiting: 100 requests/minute
- Token authentication (timing-safe comparison)
- Input validation & size limits
- Connection limits (5 concurrent max)

Change your API token in `config/config.py` before production use!

---

## 📊 Performance

- Control loop: 2000ms period, <50ms execution
- API response: <200ms typical
- Memory: ~20KB used / 264KB total (7.5%)
- Boot time: ~10 seconds

---

## 🛡️ Features

- ✅ Closed-loop temperature control with hysteresis
- ✅ Anti-short-cycle protection
- ✅ Fail-safe sensor fault handling
- ✅ Web API with live updates (SSE)
- ✅ OLED display with status icons
- ✅ Structured logging with fault codes
- ✅ **Production telemetry system with time-series storage**
- ✅ **Interactive web dashboard with real-time graphs**
- ✅ **Performance metrics and state transition logging**
- ✅ Dependency injection for testability
- ✅ Cooperative scheduling (no threading)
- ✅ WiFi auto-reconnect with retry
- ✅ Configuration profiles with validation

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Won't boot | `scripts/repl.sh` to see errors |
| No WiFi | `scripts/wifi_debug.sh` |
| Display blank | Check I2C wiring (GP0, GP1) |
| API errors | Check `./monitor` for logs |

---

## 📝 License

MIT License - Free for personal and commercial use.

---

Built with clean architecture patterns for maintainable embedded systems.
