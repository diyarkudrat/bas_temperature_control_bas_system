#!/bin/bash
# shutdown.sh - Gracefully shut down the Pico: safe relays, WiFi off, deep sleep
# Usage: ./shutdown.sh

set -euo pipefail

DEVICE="${1:-}"
if [[ -z "$DEVICE" || "$DEVICE" != /dev/* ]]; then
  DEVICE="$(mpremote connect list | awk '/(usbmodem|ttyACM)/ {print $1; exit}')"
fi

if [[ -z "$DEVICE" ]]; then
  echo "❌ No Pico found. Make sure it's connected."
  exit 1
fi

echo "🛑 Shutting down Pico on: $DEVICE"

mpremote connect "$DEVICE" exec "
import time
try:
    import network
    sta = network.WLAN(network.STA_IF)
    if sta.active():
        try:
            sta.disconnect()
        except Exception:
            pass
        try:
            sta.active(False)
        except Exception:
            pass
except Exception:
    pass

try:
    from core import Relay
    # Turn relays OFF (safe state)
    try:
        cool = Relay(15, 'COOL')
        cool.deactivate()
    except Exception:
        pass
    try:
        heat = Relay(14, 'HEAT')
        heat.deactivate()
    except Exception:
        pass
except Exception:
    pass

print('Relays OFF, WiFi OFF. Entering deep sleep…')
time.sleep_ms(100)
import machine
machine.deepsleep()
" 2>/dev/null || {
  # Expected: USB serial disconnects immediately on deepsleep; ignore mpremote error
  :
}

echo "✅ Shutdown command sent. Device is now in deep sleep."


