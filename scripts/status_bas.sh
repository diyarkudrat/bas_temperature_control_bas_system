#!/bin/bash
# status_bas.sh - Check BAS system status

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

echo "📊 BAS System Status"
echo "==================="
echo ""

# Check server status
print_info "Checking server status..."

if [ -f "server.pid" ]; then
    SERVER_PID=$(cat server.pid)
    if kill -0 $SERVER_PID 2>/dev/null; then
        print_status "Server is running (PID: $SERVER_PID)"
        
        # Check if server is responding
        if curl -s http://localhost:8080/api/health >/dev/null 2>&1; then
            print_status "Server is responding to requests"
            
            # Get current system status
            STATUS_JSON=$(curl -s http://localhost:8080/api/status 2>/dev/null || echo "{}")
            if [ "$STATUS_JSON" != "{}" ]; then
                echo ""
                print_info "Current System Status:"
                echo "$STATUS_JSON" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    temp_c = data.get('temp_tenths', 0) / 10
    setpoint_c = data.get('setpoint_tenths', 0) / 10
    deadband_c = data.get('deadband_tenths', 0) / 10
    
    print(f'  Temperature: {temp_c:.1f}°C')
    print(f'  Setpoint: {setpoint_c:.1f}°C')
    print(f'  Deadband: {deadband_c:.1f}°C')
    print(f'  State: {data.get(\"state\", \"Unknown\")}')
    print(f'  Fan: {\"ON\" if data.get(\"cool_active\") else \"OFF\"}')
    print(f'  LEDs: {\"ON\" if data.get(\"heat_active\") else \"OFF\"}')
    print(f'  Sensor: {\"OK\" if data.get(\"sensor_ok\") else \"FAULT\"}')
except:
    print('  Unable to parse status data')
"
            fi
        else
            print_warning "Server is running but not responding to requests"
        fi
    else
        print_error "Server PID file exists but process is not running"
        rm -f server.pid
    fi
else
    print_warning "Server is not running"
fi

echo ""

# Check Pico W connection
print_info "Checking Pico W connection..."

if command -v mpremote &> /dev/null; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        DEVICE=$(mpremote connect list | awk '/usbmodem/ {print $1; exit}')
    else
        DEVICE=$(mpremote connect list | awk '/ttyACM/ {print $1; exit}')
    fi
    
    if [[ -n "$DEVICE" ]]; then
        print_status "Pico W detected: $DEVICE"
        
        # Test connection
        if mpremote connect "$DEVICE" exec "print('Connection OK')" >/dev/null 2>&1; then
            print_status "Pico W is accessible"
        else
            print_warning "Pico W is detected but not accessible"
        fi
    else
        print_warning "No Pico W device detected"
        print_info "Make sure your Pico W is connected via USB"
    fi
else
    print_warning "mpremote not found - cannot check Pico W status"
fi

echo ""

# Check network configuration
print_info "Checking network configuration..."

if [ -f "pico_client.py" ]; then
    SERVER_URL=$(grep 'SERVER_URL =' pico_client.py | cut -d'"' -f2)
    WIFI_SSID=$(grep 'WIFI_SSID =' pico_client.py | cut -d'"' -f2)
    
    print_info "Pico W Configuration:"
    print_info "  Server URL: $SERVER_URL"
    print_info "  WiFi SSID: $WIFI_SSID"
    
    # Check if server URL is accessible
    if [[ "$SERVER_URL" == http://* ]]; then
        SERVER_IP=$(echo $SERVER_URL | sed 's|http://||' | cut -d':' -f1)
        if ping -c 1 -W 1 "$SERVER_IP" >/dev/null 2>&1; then
            print_status "Server IP is reachable"
        else
            print_warning "Server IP is not reachable"
        fi
    fi
else
    print_warning "pico_client.py not found"
fi

echo ""

# Check logs
print_info "Recent server logs:"
if [ -f "server/logs/server.log" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    tail -10 server/logs/server.log
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    print_warning "No server logs found"
fi

echo ""
print_info "Status check complete"
