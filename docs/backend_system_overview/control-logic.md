# Control Logic

## Temperature Control
- Hysteresis control with configurable deadband
- Anti-short-cycle protection (minimum on/off times)
- Sensor fault handling with automatic shutdown
- Fail-safe operation (turns off actuators on sensor fault)

## Communication Protocol
- HTTP POST for sensor data transmission (4096 byte buffer)
- JSON response with control commands
- 2-second update interval
- Automatic retry on communication failure
- Content-Length parsing for reliable data exchange
