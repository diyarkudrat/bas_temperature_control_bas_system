#!/bin/bash
# start_hardware.sh - Start BAS hardware (Pico W client)
# Starts the Pico W client with proper error handling and monitoring

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

echo "🔧 BAS Hardware Startup"
echo "======================"
echo ""

# Parse command line arguments
DEVICE=""
DEPLOY_ONLY=false
MONITOR_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --device)
            DEVICE="$2"
            shift 2
            ;;
        --deploy-only)
            DEPLOY_ONLY=true
            shift
            ;;
        --monitor)
            MONITOR_MODE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --device DEVICE    Specify Pico W device path"
            echo "  --deploy-only      Deploy client but don't start it"
            echo "  --monitor          Start in monitor mode (REPL access)"
            echo "  --help            Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Auto-detect and start"
            echo "  $0 --device /dev/ttyACM0              # Use specific device"
            echo "  $0 --deploy-only                     # Deploy but don't start"
            echo "  $0 --monitor                         # Start with REPL access"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Function to check prerequisites
check_prerequisites() {
    print_hardware "Checking prerequisites..."
    
    # Check if mpremote is available
    if ! command -v mpremote &> /dev/null; then
        print_error "mpremote not found"
        print_info "Please install it with: pip3 install mpremote"
        return 1
    fi
    print_status "mpremote found"
    
    # Check if pico_client.py exists
    if [ ! -f "$PICO_CLIENT_PATH" ]; then
        print_error "pico_client.py not found"
        print_info "Expected Pico client at: $PICO_CLIENT_PATH"
        return 1
    fi
    print_status "pico_client.py found"
    
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
        print_error "No Pico W device found"
        echo ""
        print_info "Troubleshooting:"
        print_info "1. Make sure your Pico W is connected via USB"
        print_info "2. Try putting it in BOOTSEL mode (hold BOOTSEL while plugging in USB)"
        print_info "3. Check if the device appears in: mpremote connect list"
        echo ""
        print_info "Manual device specification:"
        print_info "  $0 --device /dev/cu.usbmodemXXXXXX  # macOS"
        print_info "  $0 --device /dev/ttyACM0            # Linux"
        return 1
    fi
    
    print_status "Pico W detected: $DEVICE"
    return 0
}

# Function to check configuration
check_configuration() {
    print_hardware "Checking configuration..."
    
    # Check WiFi configuration
    if grep -q "YOUR_WIFI_NETWORK" "$PICO_CLIENT_PATH"; then
        print_warning "WiFi credentials not configured!"
        print_info "Please edit $PICO_CLIENT_PATH and update:"
        print_info "  WIFI_SSID = \"Your Network Name\""
        print_info "  WIFI_PASSWORD = \"Your Password\""
        echo ""
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Hardware startup cancelled. Please configure WiFi first."
            return 1
        fi
    else
        print_status "WiFi credentials configured"
    fi
    
    # Check server URL configuration
    if grep -q "192.168.1.100" "$PICO_CLIENT_PATH"; then
        print_warning "Server URL may need updating"
        SERVER_URL=$(grep 'SERVER_URL =' "$PICO_CLIENT_PATH" | cut -d'"' -f2)
        print_info "Current SERVER_URL: $SERVER_URL"
        echo ""
        read -p "Continue with current server URL? (Y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
        print_info "Please update SERVER_URL in $PICO_CLIENT_PATH first"
            return 1
        fi
    else
        print_status "Server URL configured"
    fi
    
    return 0
}

# Function to test connection
test_connection() {
    print_hardware "Testing connection to Pico W..."
    
    if ! mpremote connect "$DEVICE" exec "print('Connection test successful')" >/dev/null 2>&1; then
        print_error "Cannot connect to Pico W"
        print_info "Make sure the device is not running a program that blocks the REPL"
        print_info "Try putting it in BOOTSEL mode and running this script again"
        return 1
    fi
    
    print_status "Connection test successful"
    return 0
}

# Function to deploy client
deploy_client() {
    print_hardware "Deploying pico_client.py..."
    
    # Stop any running program
    print_info "Stopping any running program..."
    mpremote connect "$DEVICE" exec "import machine; machine.reset()" >/dev/null 2>&1 || true
    sleep 2
    
    # Deploy the client
    if mpremote connect "$DEVICE" cp "$PICO_CLIENT_PATH" :pico_client.py; then
        print_status "pico_client.py deployed successfully"
    else
        print_error "Failed to deploy pico_client.py"
        return 1
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
        return 1
    fi
    
    return 0
}

# Function to start client
start_client() {
    if [ "$MONITOR_MODE" = true ]; then
        print_hardware "Starting Pico W client in monitor mode..."
        print_info "You'll have REPL access. Press Ctrl+C to exit."
        echo ""
        mpremote connect "$DEVICE" run pico_client.py
    else
        print_hardware "Starting Pico W client..."
        print_warning "Press Ctrl+C to stop the client"
        echo ""
        mpremote connect "$DEVICE" run pico_client.py
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

# Function to show next steps
show_next_steps() {
    echo ""
    print_info "Next Steps:"
    echo "1. Start the server: ./legacy/scripts/start_bas.sh --server-only"
    echo "2. The Pico W will automatically connect and start sending data"
    echo "3. Open dashboard: http://localhost:8080"
    echo "4. Login: http://localhost:8080/auth/login"
    echo ""
}

# Main execution
main() {
    # Check prerequisites
    if ! check_prerequisites; then
        exit 1
    fi
    
    # Detect device
    if ! detect_device; then
        exit 1
    fi
    
    # Check configuration
    if ! check_configuration; then
        exit 1
    fi
    
    # Test connection
    if ! test_connection; then
        exit 1
    fi
    
    # Deploy client
    if ! deploy_client; then
        exit 1
    fi
    
    # Show hardware connections
    show_hardware_connections
    
    # Start client or exit if deploy-only
    if [ "$DEPLOY_ONLY" = true ]; then
        print_status "Deployment completed successfully!"
        show_next_steps
        exit 0
    fi
    
    # Start the client
    start_client
}

# Set up signal handlers for cleanup
cleanup() {
    echo ""
    print_info "Hardware startup interrupted"
    print_info "The Pico W client may still be running"
    print_info "To stop it, put the Pico W in BOOTSEL mode or reset it"
}

trap cleanup INT TERM

# Run main function
main
