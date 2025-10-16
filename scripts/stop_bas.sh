#!/bin/bash
# stop_bas.sh - Stop BAS system components

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

echo "🛑 BAS System Shutdown"
echo "====================="
echo ""

# Stop server
print_info "Stopping server..."

if [ -f "server.pid" ]; then
    SERVER_PID=$(cat server.pid)
    if kill -0 $SERVER_PID 2>/dev/null; then
        print_info "Stopping server (PID: $SERVER_PID)..."
        kill $SERVER_PID
        sleep 2
        
        # Force kill if still running
        if kill -0 $SERVER_PID 2>/dev/null; then
            print_warning "Force stopping server..."
            kill -9 $SERVER_PID
        fi
        
        print_status "Server stopped"
    else
        print_warning "Server was not running"
    fi
    rm -f server.pid
else
    print_warning "No server PID file found"
fi

# Kill any processes on port 8080
print_info "Checking for processes on port 8080..."
if lsof -i :8080 >/dev/null 2>&1; then
    print_warning "Found processes on port 8080, stopping them..."
    lsof -ti :8080 | xargs kill -9 2>/dev/null || true
    print_status "Port 8080 cleared"
else
    print_status "Port 8080 is free"
fi

# Clean up log files
if [ -f "server/logs/server.log" ]; then
    print_info "Archiving server logs..."
    mkdir -p server/logs
    mv server/logs/server.log "server/logs/server.log.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    print_status "Server logs archived"
fi

echo ""
print_status "BAS system shutdown complete"
print_info "All components stopped and cleaned up"
