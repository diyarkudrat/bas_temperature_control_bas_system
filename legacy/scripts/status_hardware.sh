#!/bin/bash
# status_hardware.sh - Check BAS hardware (Pico W) status
# Shows device status, connection info, and running programs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LEGACY_ROOT="$REPO_ROOT/legacy"
PICO_CLIENT_PATH="$LEGACY_ROOT/pico_client.py"

cd "$REPO_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

print_hardware() {
    echo -e "${PURPLE}🔧 $1${NC}"
}

echo "📊 BAS Hardware Status"
echo "====================="
echo ""

# Parse command line arguments
DEVICE=""
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --device)
            DEVICE="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --device DEVICE    Specify Pico W device path"
            echo "  --verbose         Show detailed information"
            echo "  --help            Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Auto-detect and check status"
            echo "  $0 --device /dev/ttyACM0              # Use specific device"
            echo "  $0 --verbose                          # Show detailed information"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Function to check mpremote availability
check_mpremote() {
    print_hardware "Checking mpremote availability..."
    
    if ! command -v mpremote &> /dev/null; then
        print_error "mpremote not found"
        print_info "Please install it with: pip3 install mpremote"
        return 1
    fi
    
    print_status "mpremote found: $(mpremote --version 2>/dev/null || echo 'version unknown')"
    return 0
}

# Function to detect Pico W device
detect_device() {
    print_hardware "Detecting Pico W device..."
    
    if [[ -n "$DEVICE" ]]; then
        print_info "Using specified device: $DEVICE"
        return 0
    fi
    
    # Auto-detect device
    if [[ "$OSTYPE" == "darwin"* ]]; then
        DEVICE=$(mpremote connect list | awk '/usbmodem/ {print $1; exit}')
    else
        DEVICE=$(mpremote connect list | awk '/ttyACM/ {print $1; exit}')
    fi
    
    if [[ -z "$DEVICE" ]]; then
        print_warning "No Pico W device found"
        print_info "Make sure your Pico W is connected via USB"
        return 1
    fi
    
    print_status "Pico W detected: $DEVICE"
    return 0
}

# Function to test connection
test_connection() {
    print_hardware "Testing connection to Pico W..."
    
    if mpremote connect "$DEVICE" exec "print('Connection test successful')" >/dev/null 2>&1; then
        print_status "Connection successful"
        return 0
    else
        print_error "Cannot connect to Pico W"
        print_info "The device may be running a program that blocks the REPL"
        return 1
    fi
}

# Function to check device info
check_device_info() {
    print_hardware "Checking device information..."
    
    # Get device info
    mpremote connect "$DEVICE" exec "
import sys, os, machine
print(f'MicroPython version: {sys.version}')
print(f'Platform: {sys.platform}')
print(f'Machine: {machine.machine()}')
print(f'Frequency: {machine.freq()} Hz')
print(f'Free memory: {os.getfree() if hasattr(os, \"getfree\") else \"unknown\"} bytes')
" 2>/dev/null || print_warning "Could not get device information"
}

# Function to check running program
check_running_program() {
    print_hardware "Checking for running program..."
    
    # Check if pico_client is running
    if mpremote connect "$DEVICE" exec "
try:
    import pico_client
    print('pico_client module is available')
    
    # Try to get some info about the running program
    try:
        import gc
        print(f'Memory usage: {gc.mem_alloc()} bytes allocated, {gc.mem_free()} bytes free')
    except:
        pass
        
except ImportError:
    print('No pico_client program running')
except Exception as e:
    print(f'Error checking program: {e}')
" >/dev/null 2>&1; then
        print_status "Program status checked"
    else
        print_warning "Could not check program status"
    fi
}

# Function to check WiFi configuration
check_wifi_config() {
    print_hardware "Checking WiFi configuration..."
    
    if [ -f "$PICO_CLIENT_PATH" ]; then
        WIFI_SSID=$(grep 'WIFI_SSID =' "$PICO_CLIENT_PATH" | cut -d'"' -f2)
        SERVER_URL=$(grep 'SERVER_URL =' "$PICO_CLIENT_PATH" | cut -d'"' -f2)
        
        print_info "WiFi SSID: $WIFI_SSID"
        print_info "Server URL: $SERVER_URL"
        
        if [[ "$WIFI_SSID" == "YOUR_WIFI_NETWORK" ]]; then
            print_warning "WiFi credentials not configured"
        else
            print_status "WiFi credentials configured"
        fi
        
        if [[ "$SERVER_URL" == "http://192.168.1.100:8080" ]]; then
            print_warning "Server URL may need updating"
        else
            print_status "Server URL configured"
        fi
    else
        print_warning "pico_client.py not found at $PICO_CLIENT_PATH"
    fi
}

# Function to check file system
check_filesystem() {
    if [ "$VERBOSE" = true ]; then
        print_hardware "Checking filesystem..."
        
        mpremote connect "$DEVICE" exec "
import os
try:
    files = os.listdir()
    print(f'Files on device: {len(files)}')
    for f in files:
        try:
            stat = os.stat(f)
            size = stat[6] if len(stat) > 6 else 0
            print(f'  {f}: {size} bytes')
        except:
            print(f'  {f}: (unable to get size)')
except Exception as e:
    print(f'Error listing files: {e}')
" 2>/dev/null || print_warning "Could not check filesystem"
    fi
}

# Function to show hardware connections
show_hardware_connections() {
    echo ""
    print_info "Hardware Connections:"
    echo "• DS18B20 Sensor → GP4 (with 4.7kΩ pull-up to 3.3V)"
    echo "• Cooling Relay → GP15"
    echo "• Heating Relay → GP14"
    echo ""
}

# Function to show troubleshooting
show_troubleshooting() {
    echo ""
    print_info "Troubleshooting:"
    echo "• If device not detected: Check USB connection and try BOOTSEL mode"
    echo "• If connection fails: Device may be running a blocking program"
    echo "• To stop program: Use ./scripts/stop_hardware.sh or reset device"
    echo "• To start program: Use ./scripts/start_hardware.sh"
    echo ""
}

# Main execution
main() {
    # Check mpremote
    if ! check_mpremote; then
        exit 1
    fi
    
    # Detect device
    if ! detect_device; then
        show_troubleshooting
        exit 1
    fi
    
    # Test connection
    if ! test_connection; then
        show_troubleshooting
        exit 1
    fi
    
    # Check device info
    check_device_info
    
    # Check running program
    check_running_program
    
    # Check WiFi configuration
    check_wifi_config
    
    # Check filesystem (verbose mode)
    check_filesystem
    
    # Show hardware connections
    show_hardware_connections
    
    print_status "Hardware status check completed"
}

# Run main function
main
