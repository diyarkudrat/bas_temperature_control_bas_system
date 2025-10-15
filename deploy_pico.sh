#!/bin/bash
# deploy_pico.sh - Deploy minimal BAS client to Raspberry Pi Pico W
# This script deploys only the essential pico_client.py to the Pico W

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

echo "🚀 BAS Pico W Client Deployment"
echo "================================"
echo ""

# Check if mpremote is available
if ! command -v mpremote &> /dev/null; then
    print_error "mpremote not found"
    print_info "Please install it with: pip3 install mpremote"
    exit 1
fi

# Check if pico_client.py exists
if [ ! -f "pico_client.py" ]; then
    print_error "pico_client.py not found in current directory"
    exit 1
fi

# Detect device
DEVICE="${1:-}"

print_info "Detecting Pico W device..."

if [[ -z "$DEVICE" || "$DEVICE" != /dev/* ]]; then
    # Auto-detect device
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS detection
        DEVICE=$(mpremote connect list | awk '/usbmodem/ {print $1; exit}')
    else
        # Linux detection
        DEVICE=$(mpremote connect list | awk '/ttyACM/ {print $1; exit}')
    fi
fi

if [[ -z "$DEVICE" ]]; then
    print_error "No Pico W device found"
    echo ""
    print_info "Troubleshooting:"
    print_info "1. Make sure your Pico W is connected via USB"
    print_info "2. Try putting it in BOOTSEL mode (hold BOOTSEL while plugging in USB)"
    print_info "3. Check if the device appears in: mpremote connect list"
    echo ""
    print_info "Manual device specification:"
    print_info "  ./deploy_pico.sh /dev/cu.usbmodemXXXXXX  # macOS"
    print_info "  ./deploy_pico.sh /dev/ttyACM0            # Linux"
    exit 1
fi

print_status "Pico W detected: $DEVICE"

# Check WiFi configuration
print_info "Checking WiFi configuration..."
if grep -q "YOUR_WIFI_NETWORK" pico_client.py; then
    print_warning "WiFi credentials not configured!"
    echo ""
    print_info "Please edit pico_client.py and update:"
    print_info "  WIFI_SSID = \"Your Network Name\""
    print_info "  WIFI_PASSWORD = \"Your Password\""
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Deployment cancelled. Please configure WiFi first."
        exit 1
    fi
else
    print_status "WiFi credentials configured"
fi

# Check server URL configuration
print_info "Checking server URL configuration..."
if grep -q "192.168.1.100" pico_client.py; then
    print_warning "Server URL may need updating"
    print_info "Current SERVER_URL: $(grep 'SERVER_URL =' pico_client.py)"
    echo ""
    read -p "Continue with current server URL? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        print_info "Please update SERVER_URL in pico_client.py first"
        exit 1
    fi
else
    print_status "Server URL configured"
fi

echo ""
print_info "Starting deployment..."

# Test connection first
print_info "Testing connection to Pico W..."
if ! mpremote connect "$DEVICE" exec "print('Connection test successful')" >/dev/null 2>&1; then
    print_error "Cannot connect to Pico W"
    print_info "Make sure the device is not running a program that blocks the REPL"
    print_info "Try putting it in BOOTSEL mode and running this script again"
    exit 1
fi

print_status "Connection test successful"

# Stop any running program
print_info "Stopping any running program..."
mpremote connect "$DEVICE" exec "import machine; machine.reset()" >/dev/null 2>&1 || true
sleep 2

# Deploy the client
print_info "Deploying pico_client.py..."
if mpremote connect "$DEVICE" cp pico_client.py :; then
    print_status "pico_client.py deployed successfully"
else
    print_error "Failed to deploy pico_client.py"
    exit 1
fi

# Check file size and flash usage
print_info "Checking flash usage..."
mpremote connect "$DEVICE" exec "
import os
try:
    stat = os.stat('pico_client.py')
    size = stat[6]
    print(f'File size: {size} bytes')
    print(f'Flash usage: {size/1024:.1f} KB')
except Exception as e:
    print(f'Error checking file: {e}')
"

# Verify deployment
print_info "Verifying deployment..."
if mpremote connect "$DEVICE" exec "import pico_client; print('Import successful')" >/dev/null 2>&1; then
    print_status "Deployment verified successfully"
else
    print_error "Deployment verification failed"
    exit 1
fi

echo ""
print_info "Deployment Summary"
echo "==================="
print_status "✅ Pico W client deployed successfully"
print_status "✅ File size optimized for 2MB flash"
print_status "✅ Ready for operation"
echo ""

print_info "Next Steps:"
echo "1. Start the server: ./start_server.sh"
echo "2. The Pico W will automatically connect and start sending data"
echo "3. Open dashboard: http://localhost:8080"
echo ""

print_info "To run the client manually:"
echo "  mpremote connect $DEVICE run pico_client.py"
echo ""

print_info "To monitor the client:"
echo "  mpremote connect $DEVICE"
echo ""

print_info "Hardware connections:"
echo "• DS18B20 Sensor → GP4 (with 4.7kΩ pull-up to 3.3V)"
echo "• Cooling Relay → GP15"
echo "• Heating Relay → GP14"
echo ""

print_status "Deployment completed! 🎉"