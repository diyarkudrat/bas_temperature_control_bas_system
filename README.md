# BAS Temperature Controller - Distributed Architecture

**Production-grade Building Automation System with Raspberry Pi Pico W + Computer Server**

A production-grade, distributed BAS (building automation system) platform featuring a Python/Flask server for authentication, REST APIs, real-time telemetry, dashboards, and alarm management, with a lightweight Pico W client handling sensor and relay I/O — designed to scale seamlessly from single-zone to multi-device control.

## 📋 Table of Contents

### **Getting Started**
- [⚡ Quick Reference](docs/QUICK_REFERENCE.md) - Essential commands and troubleshooting
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
- [🔧 GitHub Workflow](#-github-workflow)
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
- **User management**: `python3 scripts/auth_admin.py --help`
- **Login page**: http://localhost:8080/auth/login
- **Configuration**: JSON files in `config/` or environment variables

## 🔄 Setup & Daily Operations

### First-Time Setup
1. **Clone/Download** the BAS system to your computer
2. **Connect Hardware** to your Pico W (see Hardware Connections)
3. **Connect Pico W** to your computer via USB
4. **Run Setup**: `./setup.sh` (handles everything automatically)
5. **Configure WiFi** in `pico_client.py` (WIFI_SSID and WIFI_PASSWORD)
6. **Change Admin Password**: `python3 scripts/auth_admin.py reset-password admin <new_password>`
7. **Start System**: `./scripts/start_bas.sh`

### Script Organization
The BAS system uses a consolidated script structure for better organization:

```
scripts/                    # 🎯 Centralized script management
├── start_bas.sh           # 🚀 Complete system startup
├── status_bas.sh          # 📊 System status checker  
├── stop_bas.sh            # 🛑 System shutdown
├── start_hardware.sh      # 🔧 Hardware startup (Pico W)
├── status_hardware.sh     # 📊 Hardware status checker
├── stop_hardware.sh       # 🛑 Hardware shutdown
└── auth_admin.py          # 👤 User management tool
```

**Key Benefits:**
- **Unified Interface** - All operations through `scripts/` directory
- **Consistent Options** - All scripts support similar command-line options
- **Clear Separation** - System vs. hardware operations
- **Easy Maintenance** - Single source of truth for each operation

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
For dedicated hardware management and troubleshooting:

```bash
# Basic hardware operations
./scripts/start_hardware.sh                    # Auto-detect and start
./scripts/status_hardware.sh                  # Check hardware status
./scripts/stop_hardware.sh                    # Stop hardware

# Advanced hardware options
./scripts/start_hardware.sh --deploy-only      # Deploy but don't start
./scripts/start_hardware.sh --monitor         # Start with REPL access
./scripts/start_hardware.sh --device /dev/ttyACM0  # Use specific device
./scripts/status_hardware.sh --verbose        # Detailed hardware info
./scripts/stop_hardware.sh --reset           # Stop and reset device
```

#### Server-Only Operations
For server management and development:

```bash
# Start server only
./scripts/start_bas.sh --server-only

# Check server status
./scripts/status_bas.sh

# View server logs
tail -f server/logs/server.log

# Manual server startup (for debugging)
cd server && source venv/bin/activate && python3 bas_server.py
```

### Local Emulators (Redis + Firestore)

For fast, cost-free local development, you can run Redis and the Firestore emulator:

```bash
# Start emulators and export env vars for current shell
./scripts/setup_emulators.sh

# Environment variables set by the script
# USE_EMULATORS=1
# EMULATOR_REDIS_URL=redis://127.0.0.1:6379
# FIRESTORE_EMULATOR_HOST=127.0.0.1:8080
# GOOGLE_CLOUD_PROJECT=local-dev

# Then start the server as usual
./scripts/start_bas.sh --server-only
```

Notes:
- Redis config for local dev is in `infra/redis.config`.
- When `USE_EMULATORS=1`, services prefer local Redis and Firestore emulator automatically.
- If Redis/Firestore CLI tools are not installed, the script will skip starting them but still export env vars.

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
# System health check
./verify_system.sh

# Check complete system status
./scripts/status_bas.sh

# Check hardware specifically
./scripts/status_hardware.sh --verbose

# View server logs
tail -f server/logs/server.log

# Authentication troubleshooting
python3 scripts/auth_admin.py list-users
curl http://localhost:8080/api/health

# Hardware troubleshooting
./scripts/start_hardware.sh --deploy-only
./scripts/status_hardware.sh --device /dev/ttyACM0

# Server troubleshooting
./scripts/start_bas.sh --server-only

# Complete system restart
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
├── verify_system.sh       # System verification
└── README.md              # This file
```

## 🌐 API Endpoints

The BAS system provides a comprehensive REST API for temperature control, telemetry data, and system management.

📚 **Complete API Documentation**: See [API Documentation](docs/api/README.md) for detailed endpoint documentation, request/response formats, error codes, authentication requirements, and client examples.

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
cd server && source venv/bin/activate && python3 bas_server.py

# Test API
curl http://localhost:8080/api/health
```

### Testing Framework Docs

For details on writing and running tests, see:

- `tests/docs/README.md` — Index for the testing framework documentation
- `tests/docs/01-overview.md` — Overview and goals
- `tests/docs/08-running-and-coverage.md` — Running unit tests and coverage locally; CI is a future enhancement

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
| **API Integration** | [API Documentation](docs/api/README.md) | Complete REST API documentation with examples and error codes |
| **Authentication & Security** | [Authentication Documentation](docs/auth/README.md) | Complete authentication system design, implementation, and security features |
| **Development** | [README.md](docs/README.md) | Alternative project documentation with focus on core system features |

## 🔧 GitHub Workflow

This project includes a lightweight feature-capture workflow using GitHub Issues for tracking ideas, features, and technical tasks.

### Features
- **Issue Templates**: Structured forms for feature requests
- **Standardized Labels**: idea, in-progress, done, spike, tech-debt, perf, security, blocked
- **CLI Scripts**: Quick issue creation from terminal
- **Optional Automation**: TODO→Issue conversion (configurable)

📚 **Complete Workflow Documentation**: See [GitHub Workflow Documentation](.github/README-workflow.md) for detailed setup instructions, usage examples, and automation configuration.

## 📝 License

MIT License - Free for personal and commercial use.