#!/bin/bash
# stop_hardware.sh - Stop BAS hardware (Pico W client)
# Stops the Pico W client and resets the device

set -euo pipefail

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

echo "🛑 BAS Hardware Shutdown"
echo "======================="
echo ""

# Parse command line arguments
DEVICE=""
RESET_DEVICE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --device)
            DEVICE="$2"
            shift 2
            ;;
        --reset)
            RESET_DEVICE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --device DEVICE    Specify Pico W device path"
            echo "  --reset           Reset the Pico W device"
            echo "  --help            Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Auto-detect and stop"
            echo "  $0 --device /dev/ttyACM0              # Use specific device"
            echo "  $0 --reset                            # Reset device after stopping"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

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
        print_info "The device may already be stopped or disconnected"
        return 1
    fi
    
    print_status "Pico W detected: $DEVICE"
    return 0
}

# Function to stop running program
stop_program() {
    print_hardware "Stopping running program..."
    
    # Try to stop any running program gracefully
    if mpremote connect "$DEVICE" exec "print('Stopping program...')" >/dev/null 2>&1; then
        print_info "Attempting graceful shutdown..."
        
        # Try to interrupt the main loop if possible
        mpremote connect "$DEVICE" exec "
try:
    import sys
    sys.exit()
except:
    pass
" >/dev/null 2>&1 || true
        
        sleep 2
        print_status "Program stopped"
    else
        print_warning "Cannot connect to device - may already be stopped"
    fi
}

# Function to reset device
reset_device() {
    if [ "$RESET_DEVICE" = true ]; then
        print_hardware "Resetting Pico W device..."
        
        if mpremote connect "$DEVICE" exec "import machine; machine.reset()" >/dev/null 2>&1; then
            print_status "Device reset successfully"
        else
            print_warning "Could not reset device - may already be stopped"
        fi
    fi
}

# Function to check device status
check_status() {
    print_hardware "Checking device status..."
    
    if mpremote connect "$DEVICE" exec "print('Device is responsive')" >/dev/null 2>&1; then
        print_status "Device is responsive"
        
        # Check if any program is running
        if mpremote connect "$DEVICE" exec "
try:
    import pico_client
    print('pico_client module found - program may be running')
except ImportError:
    print('No program running')
" >/dev/null 2>&1; then
            print_info "Program appears to be running"
        else
            print_info "No program currently running"
        fi
    else
        print_warning "Device is not responsive"
    fi
}

# Function to show manual stop instructions
show_manual_stop() {
    echo ""
    print_info "Manual Stop Instructions:"
    echo "If the Pico W client is still running:"
    echo "1. Put the Pico W in BOOTSEL mode (hold BOOTSEL while plugging in USB)"
    echo "2. Or press the reset button on the Pico W"
    echo "3. Or disconnect and reconnect the USB cable"
    echo ""
}

# Main execution
main() {
    # Detect device
    if ! detect_device; then
        print_info "No device found - hardware may already be stopped"
        show_manual_stop
        exit 0
    fi
    
    # Check device status
    check_status
    
    # Stop running program
    stop_program
    
    # Reset device if requested
    reset_device
    
    echo ""
    print_status "Hardware shutdown completed"
    print_info "The Pico W client has been stopped"
    
    if [ "$RESET_DEVICE" = false ]; then
        show_manual_stop
    fi
}

# Run main function
main
