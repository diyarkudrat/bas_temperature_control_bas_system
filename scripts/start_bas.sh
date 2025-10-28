#!/bin/bash
# start_bas.sh - One-command startup for complete BAS system
# Starts both server and Pico W client with proper error handling

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

print_server() {
    echo -e "${PURPLE}🖥️  $1${NC}"
}

print_pico() {
    echo -e "${BLUE}📱 $1${NC}"
}

echo "🚀 BAS System - Complete Startup"
echo "================================"
echo ""

# Parse command line arguments
START_SERVER=true
START_PICO=true
DEVICE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --server-only)
            START_PICO=false
            shift
            ;;
        --hardware-only)
            START_SERVER=false
            shift
            ;;
        --device)
            DEVICE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --server-only    Start only the server"
            echo "  --hardware-only Start only the hardware (Pico W client)"
            echo "  --device DEVICE  Specify Pico W device path"
            echo "  --help          Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Start both server and hardware"
            echo "  $0 --server-only                     # Start only server"
            echo "  $0 --hardware-only --device /dev/ttyACM0 # Start only hardware with specific device"
            echo ""
            echo "Note: For hardware-only operations, consider using:"
            echo "  ./scripts/start_hardware.sh          # Dedicated hardware startup script"
            echo "  ./scripts/stop_hardware.sh            # Stop hardware"
            echo "  ./scripts/status_hardware.sh          # Check hardware status"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Function to start server in background
start_server() {
    print_server "Starting BAS Server..."

    # Check if port 8080 is available
    if lsof -i :8080 >/dev/null 2>&1; then
        print_warning "Port 8080 is already in use"
        lsof -ti :8080 | xargs kill -9 2>/dev/null || true
        sleep 2
        print_status "Port 8080 freed"
    fi

    # Start server in background using new entrypoint
    mkdir -p logs
    PYTHONPATH=. nohup python apps/api/main.py > logs/server.log 2>&1 &
    SERVER_PID=$!

    # Wait a moment for server to start
    sleep 3

    # Check if server started successfully
    if kill -0 $SERVER_PID 2>/dev/null; then
        print_status "Server started successfully (PID: $SERVER_PID)"
        print_info "Dashboard: http://localhost:8080"
        print_info "Logs: tail -f logs/server.log"
        echo $SERVER_PID > server.pid
        return 0
    else
        print_error "Failed to start server"
        print_info "Check logs/server.log for details"
        return 1
    fi
}

# Function to start Pico W client
start_pico() {
    print_pico "Starting Pico W Client..."
    
    # Check if mpremote is available
    if ! command -v mpremote &> /dev/null; then
        print_error "mpremote not found"
        print_info "Please install it with: pip3 install mpremote"
        return 1
    fi
    
    # Check if pico_client.py exists
    if [ ! -f "pico_client.py" ]; then
        print_error "pico_client.py not found"
        return 1
    fi
    
    # Detect device if not specified
    if [[ -z "$DEVICE" ]]; then
        print_info "Detecting Pico W device..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            DEVICE=$(mpremote connect list | awk '/usbmodem/ {print $1; exit}')
        else
            DEVICE=$(mpremote connect list | awk '/ttyACM/ {print $1; exit}')
        fi
    fi
    
    if [[ -z "$DEVICE" ]]; then
        print_error "No Pico W device found"
        print_info "Make sure your Pico W is connected via USB"
        print_info "Try putting it in BOOTSEL mode and running this script again"
        return 1
    fi
    
    print_status "Pico W detected: $DEVICE"
    
    # Test connection
    print_info "Testing connection to Pico W..."
    if ! mpremote connect "$DEVICE" exec "print('Connection test successful')" >/dev/null 2>&1; then
        print_error "Cannot connect to Pico W"
        print_info "Make sure the device is not running a program that blocks the REPL"
        return 1
    fi
    
    # Deploy and run client
    print_info "Deploying pico_client.py..."
    if mpremote connect "$DEVICE" cp pico_client.py :; then
        print_status "pico_client.py deployed successfully"
    else
        print_error "Failed to deploy pico_client.py"
        return 1
    fi
    
    print_info "Starting Pico W client..."
    print_warning "Press Ctrl+C to stop the client"
    echo ""
    
    # Run the client (this will block)
    mpremote connect "$DEVICE" run pico_client.py
}

# Function to cleanup on exit
cleanup() {
    echo ""
    print_info "Cleaning up..."
    
    if [ -f "server.pid" ]; then
        SERVER_PID=$(cat server.pid)
        if kill -0 $SERVER_PID 2>/dev/null; then
            print_server "Stopping server (PID: $SERVER_PID)..."
            kill $SERVER_PID
            wait $SERVER_PID 2>/dev/null || true
        fi
        rm -f server.pid
    fi
    
    print_status "Cleanup complete"
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Start components based on options
if [ "$START_SERVER" = true ]; then
    if ! start_server; then
        print_error "Failed to start server"
        exit 1
    fi
    echo ""
fi

if [ "$START_PICO" = true ]; then
    if [ "$START_SERVER" = true ]; then
        print_info "Server is running in background. Starting Pico W client..."
        echo ""
    fi
    
    # Use dedicated hardware script for better control
    print_info "Using dedicated hardware startup script..."
    ./scripts/start_hardware.sh --device "$DEVICE"
else
    # If only starting server, keep it running
    if [ "$START_SERVER" = true ]; then
        print_info "Server is running. Press Ctrl+C to stop."
        wait
    fi
fi
