#!/bin/bash
# verify.sh - Quick verification of deployed system
# Usage: ./verify.sh [device]

set -euo pipefail

DEVICE="${1:-}"
if [[ -z "$DEVICE" || "$DEVICE" != /dev/* ]]; then
  DEVICE="$(mpremote connect list | awk '/(usbmodem|ttyACM)/ {print $1; exit}')"
fi

if [[ -z "$DEVICE" ]]; then
  echo "❌ No Pico found. Make sure it's connected."
  exit 1
fi

echo "🔍 Verifying deployment on: $DEVICE"
echo ""

echo "📁 Checking file structure..."
mpremote connect "$DEVICE" ls : | head -20

echo ""
echo "🐍 Checking Python version and imports..."
mpremote connect "$DEVICE" exec "
import sys
print('Python:', sys.version)
print('Platform:', sys.platform)

# Test imports
try:
    from interfaces import TemperatureSensor, Actuator, Clock
    print('✅ Interfaces package imported')
except Exception as e:
    print('❌ Interfaces import failed:', e)

try:
    from services import ConfigManager, Logger, LoggerFactory
    print('✅ Services package imported')
except Exception as e:
    print('❌ Services import failed:', e)

try:
    from controller_v2 import CoolOnlyController
    print('✅ Controller V2 imported')
except Exception as e:
    print('❌ Controller V2 import failed:', e)

try:
    import core
    print('✅ Core package imported')
except Exception as e:
    print('❌ Core import failed:', e)
"

echo ""
echo "💾 Checking memory..."
mpremote connect "$DEVICE" exec "
import gc
gc.collect()
print(f'Free memory: {gc.mem_free():,} bytes')
print(f'Allocated memory: {gc.mem_alloc():,} bytes')
"

echo ""
echo "✅ Verification complete!"
echo ""
echo "📡 To monitor the running system:"
echo "   mpremote connect $DEVICE"
echo ""
echo "🔧 To switch versions:"
echo "   ./deploy.sh v1  # Original version"
echo "   ./deploy.sh v2  # Refactored version"

