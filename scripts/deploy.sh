#!/bin/bash
# deploy.sh — Sync project to Raspberry Pi Pico W via mpremote (macOS/Linux)
# Usage:
#   ./deploy.sh                              # deploy to auto-detected device
#   ./deploy.sh /dev/cu.usbmodem114401       # deploy to specific device

set -euo pipefail

DEVICE="${1:-}"

# Detect device (mac: usbmodem; linux: ttyACM)
if [[ -z "$DEVICE" || "$DEVICE" != /dev/* ]]; then
  DEVICE="$(mpremote connect list | awk '/(usbmodem|ttyACM)/ {print $1; exit}')"
fi
if [[ -z "$DEVICE" ]]; then
  echo "❌ No Pico found. Plug it in, or pass device path explicitly: ./deploy.sh /dev/cu.usbmodem114401"
  exit 1
fi

echo "📦 Deploying to Pico on: $DEVICE"
echo "📂 Uploading project files…"

# Touch config files to force update (update timestamp)
echo "  → Refreshing file timestamps..."
touch config/config.py
touch config/__init__.py
touch core/*.py
touch *.py

# Upload directories
echo "  → Uploading core/..."
mpremote connect "$DEVICE" cp -r core :
echo "  → Uploading config/..."
mpremote connect "$DEVICE" cp -r config :
echo "  → Uploading netctrl/..."
mpremote connect "$DEVICE" cp -r netctrl :
echo "  → Uploading interfaces/..."
mpremote connect "$DEVICE" cp -r interfaces :
echo "  → Uploading services/..."
mpremote connect "$DEVICE" cp -r services :
echo "  → Uploading blueprints/..."
mpremote connect "$DEVICE" cp -r blueprints :
echo "  → Uploading tests/..."
mpremote connect "$DEVICE" cp -r tests :

# Upload Python files
echo "  → Uploading Python files..."
mpremote connect "$DEVICE" cp controller.py :controller.py
mpremote connect "$DEVICE" cp display.py :display.py
mpremote connect "$DEVICE" cp main.py :main.py
mpremote connect "$DEVICE" cp ssd1306.py :ssd1306.py
mpremote connect "$DEVICE" cp boot.py :boot.py

echo "🔁 Rebooting Pico…"
# Note: Connection will drop during reboot, so we ignore the error
mpremote connect "$DEVICE" exec "import machine; machine.reset()" 2>/dev/null || true

echo "✅ Deployment complete. Pico is rebooting..."
echo "💡 Wait 5 seconds, then connect with: mpremote connect $DEVICE"
