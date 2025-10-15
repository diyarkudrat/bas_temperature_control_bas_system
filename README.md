# BAS Temperature Controller - Distributed Architecture

**Production-grade Building Automation System with Raspberry Pi Pico W + Computer Server**

A distributed temperature control system that solves Pico W storage limitations by running the web interface and control logic on your computer while the Pico W handles only essential hardware operations.

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

## 🚀 Quick Start - One-Command Setup

### Option 1: Complete System Setup (Recommended)
```bash
./setup.sh
```
This single command handles everything:
- ✅ Checks system requirements (Python 3, pip3, mpremote)
- ✅ Sets up server environment with virtual environment
- ✅ Installs Python dependencies (Flask, Flask-CORS)
- ✅ Auto-detects your computer's IP address
- ✅ Updates the Pico client configuration
- ✅ Makes all scripts executable

### Option 2: Manual Setup
If you prefer step-by-step control:

1. **Configure WiFi Credentials**
   Edit `pico_client.py` and update:
   ```python
   WIFI_SSID = "Your WiFi Network Name"
   WIFI_PASSWORD = "Your WiFi Password"
   ```

2. **Deploy Pico W Client**
   ```bash
   ./deploy_pico.sh
   ```

3. **Start the Server**
   ```bash
   ./start_server.sh
   ```

4. **Access the Dashboard**
   Open your browser: `http://localhost:8080`

## 🎮 One-Command Operations

### Complete System Control
```bash
# Start everything (server + Pico W client)
./scripts/start_bas.sh

# Start only the server
./scripts/start_bas.sh --server-only

# Start only the Pico W client
./scripts/start_bas.sh --pico-only

# Check system status
./scripts/status_bas.sh

# Stop everything
./scripts/stop_bas.sh
```

### Manual Operations
```bash
# Start server only (in one terminal)
./start_server.sh

# Deploy and run Pico client (in another terminal)
./deploy_pico.sh && mpremote connect /dev/cu.usbmodem* run pico_client.py

# Verify system setup
./verify_system.sh
```

## 📁 Project Structure

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
│   ├── start_bas.sh        # 🚀 One-command system startup
│   ├── status_bas.sh       # 📊 System status checker
│   └── stop_bas.sh         # 🛑 System shutdown
├── setup.sh               # Complete system setup
├── deploy_pico.sh         # Deploy Pico client
├── start_server.sh        # Start server only
├── verify_system.sh       # System verification
└── README.md              # This file
```

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

## 🌐 Web Dashboard Features

### Real-time Monitoring
- **Current temperature** with live updates
- **System state** (IDLE, COOLING, HEATING, FAULT)
- **Actuator status** (ON/OFF indicators)
- **Sensor health** monitoring

### Interactive Controls
- **Setpoint adjustment** (10.0°C to 40.0°C)
- **Deadband configuration** (0.0°C to 5.0°C)
- **Real-time parameter updates**

### Data Visualization
- **Temperature history graph** with Chart.js
- **Setpoint visualization** on the same chart
- **Historical data** from SQLite database

### Connection Status
- **Live connection indicator** to Pico W
- **Automatic reconnection** handling
- **Error reporting** and status messages

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

## 🔄 Complete Deployment Workflow

### First-Time Setup
1. **Clone/Download** the BAS system to your computer
2. **Connect Hardware** to your Pico W (see Hardware Connections)
3. **Connect Pico W** to your computer via USB
4. **Run Setup**: `./setup.sh` (handles everything automatically)
5. **Start System**: `./scripts/start_bas.sh`

### Daily Operations
```bash
# Start the complete system
./scripts/start_bas.sh

# Check status anytime
./scripts/status_bas.sh

# Stop when done
./scripts/stop_bas.sh
```

### Development Workflow
```bash
# Server development
cd server
source venv/bin/activate
python bas_server.py

# Pico W development
mpremote connect /dev/cu.usbmodem* repl
mpremote connect /dev/cu.usbmodem* run pico_client.py
mpremote connect /dev/cu.usbmodem* edit pico_client.py
```

### Troubleshooting Workflow
```bash
# Check system health
./verify_system.sh

# Check current status
./scripts/status_bas.sh

# View server logs
tail -f server.log

# Restart everything
./scripts/stop_bas.sh && ./scripts/start_bas.sh
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard |
| `/api/status` | GET | System status |
| `/api/sensor_data` | POST | Receive sensor data |
| `/api/set_setpoint` | POST | Update setpoint/deadband |
| `/api/telemetry` | GET | Historical data |
| `/api/health` | GET | Health check |

## 🔒 Security

### Network Security
- **Local network only** - No internet exposure required
- **WiFi encryption** - Use WPA2/WPA3 networks
- **Input validation** - All parameters validated
- **Error handling** - Graceful failure modes

### Data Protection
- **Local database** - No cloud dependencies
- **Connection monitoring** - Automatic fault detection
- **Safe defaults** - Conservative control parameters

## 📱 Mobile Access

The web dashboard is **mobile-responsive** and works on:
- **Smartphones** - iOS and Android
- **Tablets** - iPad and Android tablets
- **Laptops** - Windows, Mac, Linux
- **Any device** with a web browser

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

## 📈 Performance

### Pico W Client
- **Memory usage**: ~15KB RAM / 2MB Flash
- **Update rate**: 2-second intervals
- **Power consumption**: ~100mA active
- **Reliability**: Designed for 24/7 operation

### Computer Server
- **Response time**: <100ms typical
- **Database**: SQLite with automatic cleanup
- **Concurrent connections**: Multiple Pico W support
- **Data retention**: 7 days automatic cleanup

## 🚀 Future Enhancements

### Planned Features
- **Multiple zone support** for complex systems
- **MQTT integration** for cloud connectivity
- **Mobile app** for remote monitoring
- **Advanced analytics** and reporting

### Extensibility
- **Custom sensor support** through plugin system
- **Additional actuators** (fans, pumps, valves)
- **Integration APIs** for home automation systems
- **Backup and restore** functionality

## 📝 License

MIT License - Free for personal and commercial use.

## 🤝 Contributing

Contributions welcome! Please see the development guidelines and submit pull requests for:
- Bug fixes
- New features
- Documentation improvements
- Hardware support additions

---

**Built with clean architecture principles for reliable embedded systems.**

*This distributed architecture solves the Pico W storage limitations while providing a full-featured temperature control system.*