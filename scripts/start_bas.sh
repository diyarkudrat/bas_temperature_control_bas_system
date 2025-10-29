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

# Load project env if available
if [ -f "config/auth.env" ]; then
    print_info "Loading environment from config/auth.env"
    set -a
    # shellcheck disable=SC1091
    source config/auth.env
    set +a
    print_status "Loaded environment from config/auth.env"
fi

# Ensure Python 3 virtual environment and dependencies
setup_python_env() {
    # Find a good CPython 3.x interpreter (prefer Homebrew); allow override via $PYTHON_BIN
    find_python() {
        local candidates=()
        if [ -n "${PYTHON_BIN:-}" ]; then candidates+=("$PYTHON_BIN"); fi
        # Prefer known stable versions first to avoid 3.14 package incompatibilities
        candidates+=(
            "/opt/homebrew/bin/python3.12" "/usr/local/bin/python3.12" "/usr/bin/python3.12"
            "/opt/homebrew/bin/python3.11" "/usr/local/bin/python3.11" "/usr/bin/python3.11"
            "/opt/homebrew/bin/python3.10" "/usr/local/bin/python3.10" "/usr/bin/python3.10"
            "/opt/homebrew/bin/python3" "$(command -v python3 2>/dev/null)" "/usr/local/bin/python3" "/usr/bin/python3"
        )
        for cand in "${candidates[@]}"; do
            if [ -x "$cand" ]; then
                if "$cand" - <<'PYTEST' >/dev/null 2>&1
import sys
assert (3, 10) <= sys.version_info < (3, 14)
import http.server, ssl, asyncio
PYTEST
                then
                    echo "$cand"
                    return 0
                fi
            fi
        done
        return 1
    }

    local BASE_PY
    BASE_PY=$(find_python) || { print_error "No suitable CPython3 found (>=3.10 with stdlib). Install Homebrew python3."; exit 1; }

    # Prefer .venv; recreate if missing or broken
    local WANT_VENV_BIN=".venv/bin/python3"
    local NEED_RECREATE=0
    if [ -x "$WANT_VENV_BIN" ]; then
        if ! "$WANT_VENV_BIN" - <<'PYTEST' >/dev/null 2>&1
import http.server, ssl, asyncio
PYTEST
        then
            print_warning ".venv is broken (stdlib missing); recreating"
            NEED_RECREATE=1
        else
            # Recreate if venv uses unsupported Python version (>=3.14)
            if ! "$WANT_VENV_BIN" - <<'PYTEST' >/dev/null 2>&1
import sys
import sys
raise SystemExit(0 if sys.version_info < (3,14) and sys.version_info >= (3,10) else 1)
PYTEST
            then
                print_warning ".venv Python version unsupported; recreating"
                NEED_RECREATE=1
            fi
        fi
    else
        NEED_RECREATE=1
    fi

    if [ $NEED_RECREATE -eq 1 ]; then
        print_info "Creating virtual environment at .venv using ${BASE_PY}"
        "$BASE_PY" -m venv .venv || { print_error "Failed to create virtual environment (.venv)"; exit 1; }
        print_status "Virtual environment created at .venv"
    fi

    PY_BIN="$WANT_VENV_BIN"
    print_status "Using virtual environment at .venv/"

    # Ensure pip present; install requirements if Flask missing or forced
    if [ -f "apps/api/requirements.txt" ]; then
        "$PY_BIN" -m pip --version >/dev/null 2>&1 || "$PY_BIN" -m ensurepip -U >/dev/null 2>&1 || true
        if ! "$PY_BIN" -c "import flask" >/dev/null 2>&1 || [ "${FORCE_PIP_INSTALL:-0}" = "1" ]; then
            print_info "Installing Python dependencies from apps/api/requirements.txt"
            "$PY_BIN" -m pip install -U pip || true
            "$PY_BIN" -m pip install -r apps/api/requirements.txt || { print_error "Dependency installation failed"; exit 1; }
            print_status "Dependencies installed"
        fi
    fi
}

# Function to start server in background
start_server() {
    print_server "Starting BAS Server..."

    # Decide which port to use (honor existing PORT env; default 8080)
    local PORT_TO_USE="${PORT:-8080}"

    # Check if chosen port is available; try to free, else fall back to another
    if lsof -i :"${PORT_TO_USE}" >/dev/null 2>&1; then
        print_warning "Port ${PORT_TO_USE} is already in use"
        lsof -ti :"${PORT_TO_USE}" | xargs kill -9 2>/dev/null || true
        sleep 2
        if lsof -i :"${PORT_TO_USE}" >/dev/null 2>&1; then
            print_warning "Port ${PORT_TO_USE} still in use, selecting alternate port"
            for p in 8081 8082 8083 8084 8085 8090 8091 8092; do
                if ! lsof -i :"$p" >/dev/null 2>&1; then
                    PORT_TO_USE="$p"
                    print_status "Selected alternate port ${PORT_TO_USE}"
                    break
                fi
            done
        else
            print_status "Port ${PORT_TO_USE} freed"
        fi
    fi

    # Start server in background using new entrypoint
    local LOG_FILE="server.log"
    local PY_CMD="${PY_BIN:-${PYTHON_BIN:-}}"
    if [[ -z "$PY_CMD" ]]; then
        if command -v python3 >/dev/null 2>&1; then
            PY_CMD="python3"
        elif command -v python >/dev/null 2>&1; then
            PY_CMD="python"
        else
            print_error "Python interpreter not found (python3/python). Please install Python 3."
            return 1
        fi
    fi

    # Sanitize Python env to avoid broken search paths
    unset PYTHONHOME || true
    unset PYTHONPATH || true
    PORT=${PORT_TO_USE} nohup "$PY_CMD" -m apps.api.main > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!

    # Wait a moment for server to start
    sleep 3

    # Check if server started successfully
    if kill -0 $SERVER_PID 2>/dev/null; then
        print_status "Server started successfully (PID: $SERVER_PID)"
        print_info "Dashboard: http://localhost:${PORT_TO_USE}"
        print_info "Logs: tail -f server.log"
        echo $SERVER_PID > server.pid
        return 0
    else
        print_error "Failed to start server"
        print_info "Check server.log for details"
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
    # Prepare Python environment (venv + deps)
    setup_python_env
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
