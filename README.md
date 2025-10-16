# BAS Temperature Controller - Distributed Architecture

**Production-grade Building Automation System with Raspberry Pi Pico W + Computer Server**

A distributed temperature control system that solves Pico W storage limitations by running the web interface and control logic on your computer while the Pico W handles only essential hardware operations.

## 📋 Table of Contents

### **Getting Started**
- [🏗️ Architecture Overview](#️-architecture-overview)
- [🔧 Hardware Connections](#-hardware-connections)
- [🚀 Quick Start & Setup](#-quick-start--setup)
- [🔄 Setup & Daily Operations](#-setup--daily-operations)

### **System Usage**
- [🎮 System Operations](#-system-operations)
- [📊 Control Logic](#-control-logic)
- [🌐 API Endpoints](#-api-endpoints)

### **Troubleshooting & Support**
- [🐛 Troubleshooting](#-troubleshooting)
- [🎯 Use Cases](#-use-cases)

### **Advanced Topics**
- [📚 Detailed Documentation](#-detailed-documentation)
- [📝 License](#-license)

## 🏗️ Architecture Overview

```
┌─────────────────┐    WiFi    ┌─────────────────┐
│   Your Computer │◄─────────►│   Raspberry Pi  │
│   (Full Server) │           │   Pico W        │
│                 │           │   (Minimal)     │
│ • Web Interface │           │ • Temperature   │
│ • Control Logic │           │   Sensor        │
│ • Database      │           │ • Relays        │
│ • Telemetry     │           │ • Basic I/O     │
└─────────────────┘           └─────────────────┘
```

### ✅ Benefits of This Architecture

**Pico W Advantages:**
- **Minimal storage usage** - Only essential hardware drivers
- **Fast deployment** - Small files transfer quickly
- **Reliable operation** - Simple, focused functionality
- **Low power consumption** - Efficient sensor/actuator control

**Computer Server Advantages:**
- **Full web interface** - Rich dashboard with real-time graphs
- **Data storage** - SQLite database for telemetry
- **Control logic** - Complex temperature control algorithms
- **Scalability** - Can control multiple Pico W devices

## 🔧 Hardware Connections

Connect these components to your Raspberry Pi Pico W:

| Component | GPIO Pin | Notes |
|-----------|----------|-------|
| DS18B20 Sensor | GP4 | 1-Wire + 4.7kΩ pull-up |
| Cooling Relay | GP15 | Active-HIGH |
| Heating Relay | GP14 | Active-HIGH |

### Wiring Diagram
```
Pico W          DS18B20
GP4 ──────────── Data (with 4.7kΩ pull-up to 3.3V)
GND ──────────── GND
3.3V ─────────── VCC

Pico W          Relays
GP14 ─────────── Heating Relay Control
GP15 ─────────── Cooling Relay Control
GND ──────────── Relay GND
3.3V ─────────── Relay VCC
```

## 🚀 Quick Start & Setup

### Complete System Setup (Recommended)
```bash
./setup.sh
```
This single command handles everything:
- ✅ Checks system requirements (Python 3, pip3, mpremote)
- ✅ Sets up server environment with virtual environment
- ✅ Installs Python dependencies (Flask, Flask-CORS, Twilio)
- ✅ Configures authentication system with default admin user
- ✅ Auto-detects your computer's IP address
- ✅ Updates the Pico client configuration
- ✅ Makes all scripts executable

### Authentication Setup
The system includes a complete authentication system:
- **Default admin user**: `admin` / `Admin123!@#X` (change immediately!)
- **User management**: `python scripts/auth_admin.py --help`
- **Login page**: http://localhost:8080/auth/login
- **Configuration**: JSON files in `config/` or environment variables

## 🔄 Setup & Daily Operations

### First-Time Setup
1. **Clone/Download** the BAS system to your computer
2. **Connect Hardware** to your Pico W (see Hardware Connections)
3. **Connect Pico W** to your computer via USB
4. **Run Setup**: `./setup.sh` (handles everything automatically)
5. **Configure WiFi** in `pico_client.py` (WIFI_SSID and WIFI_PASSWORD)
6. **Change Admin Password**: `python scripts/auth_admin.py reset-password admin <new_password>`
7. **Start System**: `./scripts/start_bas.sh`

### Daily Operations

#### Complete System Control
```bash
# Start the complete system (server + hardware)
./scripts/start_bas.sh

# Start only the server
./scripts/start_bas.sh --server-only

# Start only the hardware (Pico W client)
./scripts/start_bas.sh --hardware-only

# Check system status
./scripts/status_bas.sh

# Stop the complete system
./scripts/stop_bas.sh
```

#### Hardware-Only Operations
For dedicated hardware management, use the specialized hardware scripts:

```bash
# Start hardware (Pico W client)
./scripts/start_hardware.sh

# Check hardware status
./scripts/status_hardware.sh

# Stop hardware
./scripts/stop_hardware.sh

# Advanced hardware options
./scripts/start_hardware.sh --deploy-only    # Deploy but don't start
./scripts/start_hardware.sh --monitor       # Start with REPL access
./scripts/stop_hardware.sh --reset          # Stop and reset device
```

### Authentication & User Management
The system includes comprehensive authentication with user management:

```bash
# User management commands
python3 scripts/auth_admin.py create-user john password123 +1234567890 --role operator
python3 scripts/auth_admin.py list-users
python3 scripts/auth_admin.py reset-password admin newpassword
python3 scripts/auth_admin.py unlock-user john
python3 scripts/auth_admin.py delete-user john

# Configuration options
# Method 1: JSON files (default)
cp config/templates/secrets.json.template config/secrets.json
# Edit config/secrets.json with Twilio credentials

# Method 2: Environment variables
cp config/auth.example.env .env
# Edit .env with your settings
```

### Troubleshooting Workflow
```bash
# Check system health
./verify_system.sh

# Check current status
./scripts/status_bas.sh

# Check hardware specifically
./scripts/status_hardware.sh --verbose

# View server logs
tail -f server/logs/server.log

# Authentication troubleshooting
python scripts/auth_admin.py list-users
curl http://localhost:8080/api/health

# Hardware troubleshooting
./scripts/start_hardware.sh --deploy-only
./scripts/status_hardware.sh --device /dev/ttyACM0

# Restart everything
./scripts/stop_bas.sh && ./scripts/start_bas.sh
```

## 🎮 System Operations

### Complete System Control
```bash
# Start everything (server + hardware)
./scripts/start_bas.sh

# Start only the server
./scripts/start_bas.sh --server-only

# Start only the hardware (Pico W client)
./scripts/start_bas.sh --hardware-only

# Check system status
./scripts/status_bas.sh

# Stop everything
./scripts/stop_bas.sh
```

### Dedicated Hardware Management
For advanced hardware control and troubleshooting:

```bash
# Hardware startup with options
./scripts/start_hardware.sh                    # Auto-detect and start
./scripts/start_hardware.sh --device /dev/ttyACM0  # Use specific device
./scripts/start_hardware.sh --deploy-only     # Deploy but don't start
./scripts/start_hardware.sh --monitor         # Start with REPL access

# Hardware status and diagnostics
./scripts/status_hardware.sh                   # Basic status check
./scripts/status_hardware.sh --verbose         # Detailed information
./scripts/status_hardware.sh --device /dev/ttyACM0  # Check specific device

# Hardware shutdown
./scripts/stop_hardware.sh                     # Graceful stop
./scripts/stop_hardware.sh --reset            # Stop and reset device
```

## 📊 Control Logic

### Temperature Control
- **Hysteresis control** with configurable deadband
- **Anti-short-cycle protection** (minimum on/off times)
- **Sensor fault handling** with automatic shutdown
- **Fail-safe operation** (turns off actuators on sensor fault)

### Communication Protocol
- **HTTP POST** for sensor data transmission (4096 byte buffer)
- **JSON response** with control commands
- **2-second update interval**
- **Automatic retry** on communication failure
- **Content-Length parsing** for reliable data exchange

### Project Structure

```
BAS System Project/
├── pico_client.py          # Minimal Pico W client (11.4KB)
├── server/                 # Computer-based server
│   ├── bas_server.py       # Flask web server
│   ├── bas_telemetry.db    # SQLite database
│   ├── templates/          # Web dashboard
│   ├── requirements.txt    # Python dependencies
│   └── setup_server.sh     # Server setup script
├── scripts/                # System control scripts
│   ├── start_bas.sh        # 🚀 Complete system startup
│   ├── status_bas.sh       # 📊 System status checker
│   ├── stop_bas.sh         # 🛑 System shutdown
│   ├── start_hardware.sh   # 🔧 Hardware startup (Pico W)
│   ├── status_hardware.sh  # 📊 Hardware status checker
│   ├── stop_hardware.sh    # 🛑 Hardware shutdown
│   └── auth_admin.py       # 👤 User management tool
├── setup.sh               # Complete system setup
├── deploy_pico.sh         # Deploy Pico client
├── start_server.sh        # Start server only
├── verify_system.sh       # System verification
└── README.md              # This file
```

## 🌐 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard |
| `/api/status` | GET | System status |
| `/api/sensor_data` | POST | Receive sensor data from Pico W |
| `/api/set_setpoint` | POST | Update setpoint/deadband |
| `/api/telemetry` | GET | Historical telemetry data |
| `/api/config` | GET | System configuration |
| `/api/health` | GET | Health check |

### Quick API Examples

```bash
# Check system health
curl http://localhost:8080/api/health

# Get current status
curl http://localhost:8080/api/status

# Update setpoint to 25.0°C
curl -X POST http://localhost:8080/api/set_setpoint \
  -H "Content-Type: application/json" \
  -d '{"setpoint_tenths": 250}'

# Get system configuration
curl http://localhost:8080/api/config

# Get last 20 telemetry points
curl "http://localhost:8080/api/telemetry?limit=20"
```

📚 **Complete API Documentation**: See [API_REFERENCE.md](docs/API_REFERENCE.md) for detailed endpoint documentation, request/response formats, error codes, and client examples.

## 🐛 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Pico W not found | Check USB connection, try BOOTSEL mode |
| WiFi connection fails | Verify credentials in pico_client.py |
| Server won't start | Run `cd server && ./setup_server.sh` |
| No data from Pico | Check IP address in SERVER_URL |
| Dashboard not loading | Check server is running on port 8080 |

### Debug Commands
```bash
# Check Pico W connection
mpremote connect /dev/cu.usbmodem* exec "import network; print(network.WLAN().ifconfig())"

# Check server logs
cd server && source venv/bin/activate && python bas_server.py

# Test API
curl http://localhost:8080/api/health
```

## 🎯 Use Cases

### Home Automation
- **HVAC control** for individual rooms
- **Temperature monitoring** with alerts
- **Energy efficiency** through smart control

### Industrial Applications
- **Process control** for small systems
- **Environmental monitoring** in controlled spaces
- **Equipment protection** through temperature limits

### Research & Development
- **Prototype testing** with real-time data
- **Control algorithm development**
- **Sensor validation** and calibration


## 📚 Detailed Documentation

The BAS system includes comprehensive documentation for developers, system administrators, and integrators:

| **Category** | **Document** | **Description** |
|--------------|--------------|-----------------|
| **System Architecture** | [SYSTEM_OVERVIEW.md](docs/SYSTEM_OVERVIEW.md) | Complete system architecture, component diagrams, and design principles |
| **API Integration** | [API_REFERENCE.md](docs/API_REFERENCE.md) | Complete REST API documentation with examples and error codes |
| **Security** | [AUTH_ENHANCEMENTS.md](docs/AUTH_ENHANCEMENTS.md) | Comprehensive security enhancements and modern authentication best practices |
| **Authentication** | [SECURITY_AUTH_PLAN.md](docs/SECURITY_AUTH_PLAN.md) | Complete authentication system design and implementation plan |
| **Development** | [README.md](docs/README.md) | Alternative project documentation with focus on core system features |

## 📝 License

MIT License - Free for personal and commercial use.