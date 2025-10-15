#!/bin/bash
# repl.sh - Open interactive REPL on Pico
# Usage: ./repl.sh

DEVICE="${1:-}"
if [[ -z "$DEVICE" || "$DEVICE" != /dev/* ]]; then
  DEVICE="$(mpremote connect list | awk '/(usbmodem|ttyACM)/ {print $1; exit}')"
fi

if [[ -z "$DEVICE" ]]; then
  echo "❌ No Pico found. Make sure it's connected."
  exit 1
fi

echo "🐍 Opening MicroPython REPL on: $DEVICE"
echo "💡 Tips:"
echo "   - Type Python commands directly"
echo "   - Ctrl+C to interrupt running program"
echo "   - Ctrl+D to soft reboot"
echo "   - Ctrl+X to exit"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Connect to REPL
mpremote connect "$DEVICE" repl

