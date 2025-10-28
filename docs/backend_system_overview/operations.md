# Operations

## Complete System Control
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

## Hardware-Only Operations
```bash
./scripts/start_hardware.sh                    # Auto-detect and start
./scripts/status_hardware.sh                  # Check hardware status
./scripts/stop_hardware.sh                    # Stop hardware

# Advanced options
./scripts/start_hardware.sh --deploy-only      # Deploy but don't start
./scripts/start_hardware.sh --monitor         # Start with REPL access
./scripts/start_hardware.sh --device /dev/ttyACM0  # Use specific device
./scripts/status_hardware.sh --verbose        # Detailed hardware info
./scripts/stop_hardware.sh --reset           # Stop and reset device
```

## Server-Only Operations
```bash
./scripts/start_bas.sh --server-only
./scripts/status_bas.sh

# View server logs
tail -f server/logs/server.log
```

## Local Emulators (Redis + Firestore)
```bash
# Start emulators and export env vars for current shell
./scripts/setup_emulators.sh

# Then start the server as usual
./scripts/start_bas.sh --server-only
```
