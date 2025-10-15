#!/bin/bash
# status.sh - Quick status check without interrupting the program
# Usage: ./status.sh

DEVICE="${1:-}"
if [[ -z "$DEVICE" || "$DEVICE" != /dev/* ]]; then
  DEVICE="$(mpremote connect list | awk '/(usbmodem|ttyACM)/ {print $1; exit}')"
fi

if [[ -z "$DEVICE" ]]; then
  echo "❌ No Pico found. Make sure it's connected."
  exit 1
fi

echo "📊 Pico Status Check"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "💾 Memory:"
mpremote connect "$DEVICE" exec "
import gc
gc.collect()
free = gc.mem_free()
alloc = gc.mem_alloc()
total = free + alloc
print(f'  Free:      {free:,} bytes ({free/total*100:.1f}%)')
print(f'  Allocated: {alloc:,} bytes ({alloc/total*100:.1f}%)')
print(f'  Total:     {total:,} bytes')
"

echo ""
echo "⏱️  Uptime:"
mpremote connect "$DEVICE" exec "
import time
uptime_ms = time.ticks_ms()
uptime_s = uptime_ms // 1000
hours = uptime_s // 3600
minutes = (uptime_s % 3600) // 60
seconds = uptime_s % 60
print(f'  {hours}h {minutes}m {seconds}s ({uptime_s:,} seconds)')
"

echo ""
echo "🌡️  Sensor:"
mpremote connect "$DEVICE" exec "
try:
    from core import DS18B20Sensor
    sensor = DS18B20Sensor(4)
    reading = sensor.read()
    if reading.is_valid:
        print(f'  Temperature: {reading.temp_tenths/10:.1f}°C')
        print(f'  Status: OK ✅')
    else:
        print(f'  Status: FAULT ❌ (Error code: {reading.error_code})')
except Exception as e:
    print(f'  Error: {e}')
"

echo ""
echo "🔧 Relays:"
mpremote connect "$DEVICE" exec "
try:
    from core import Relay
    cool = Relay(15, 'COOL')
    heat = Relay(14, 'HEAT')
    print(f'  Cooling: {'ON ✅' if cool.is_on() else 'OFF'}')
    print(f'  Heating: {'ON ✅' if heat.is_on() else 'OFF'}')
except Exception as e:
    print(f'  Error: {e}')
"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

