#!/bin/bash
# monitor.sh - Connect to Pico and monitor real-time output
# Usage: ./monitor.sh

DEVICE="${1:-}"
if [[ -z "$DEVICE" || "$DEVICE" != /dev/* ]]; then
  DEVICE="$(mpremote connect list | awk '/(usbmodem|ttyACM)/ {print $1; exit}')"
fi

if [[ -z "$DEVICE" ]]; then
  echo "❌ No Pico found. Make sure it's connected."
  exit 1
fi

echo "🔌 Connecting to Pico on: $DEVICE"
echo "📡 Monitoring output... (Ctrl+X to exit)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Connect and show output
mpremote connect "$DEVICE"

