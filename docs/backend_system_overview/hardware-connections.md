# Hardware Connections

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
