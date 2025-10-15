#!/bin/bash
# start_server.sh - Start the BAS server with proper environment setup

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

echo "🌐 BAS Server Startup"
echo "===================="
echo ""

# Check if server directory exists
if [ ! -d "server" ]; then
    print_error "Server directory not found"
    print_info "Please run ./setup.sh first"
    exit 1
fi

cd server

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    print_warning "Virtual environment not found"
    print_info "Running server setup..."
    
    if [ -f "setup_server.sh" ]; then
        chmod +x setup_server.sh
        ./setup_server.sh
        if [ $? -eq 0 ]; then
            print_status "Server setup completed"
        else
            print_error "Server setup failed"
            exit 1
        fi
    else
        print_error "Server setup script not found"
        exit 1
    fi
fi

# Check if bas_server.py exists
if [ ! -f "bas_server.py" ]; then
    print_error "bas_server.py not found"
    exit 1
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source venv/bin/activate

# Check if Flask is installed
print_info "Checking dependencies..."
if ! python -c "import flask" 2>/dev/null; then
    print_warning "Flask not found, installing dependencies..."
    pip install -r requirements.txt
    if [ $? -eq 0 ]; then
        print_status "Dependencies installed"
    else
        print_error "Failed to install dependencies"
        exit 1
    fi
else
    print_status "Dependencies verified"
fi

# Check if port 8080 is available
print_info "Checking port availability..."
if lsof -i :8080 >/dev/null 2>&1; then
    print_warning "Port 8080 is already in use"
    print_info "Processes using port 8080:"
    lsof -i :8080
    echo ""
    read -p "Kill existing processes and continue? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Killing processes on port 8080..."
        lsof -ti :8080 | xargs kill -9 2>/dev/null || true
        sleep 2
        print_status "Port 8080 freed"
    else
        print_info "Please stop the conflicting process and try again"
        exit 1
    fi
else
    print_status "Port 8080 is available"
fi

# Get computer IP address for display
print_info "Detecting network configuration..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    COMPUTER_IP=$(ifconfig | grep -E "inet.*broadcast" | awk '{print $2}' | head -1)
else
    COMPUTER_IP=$(ip route get 8.8.8.8 | grep -oP 'src \K\S+' | head -1)
fi

echo ""
print_info "Starting BAS Server..."
print_info "Dashboard will be available at:"
print_info "  • http://localhost:8080"
if [ -n "$COMPUTER_IP" ]; then
    print_info "  • http://$COMPUTER_IP:8080"
fi
echo ""
print_info "API endpoints:"
print_info "  • /api/status - System status"
print_info "  • /api/sensor_data - Receive data from Pico"
print_info "  • /api/set_setpoint - Update control parameters"
print_info "  • /api/telemetry - Historical data"
echo ""
print_warning "Press Ctrl+C to stop the server"
echo ""

# Start the server
print_status "Starting server..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Run the server with proper error handling
python bas_server.py

# This will only be reached if the server exits normally
echo ""
print_info "Server stopped"