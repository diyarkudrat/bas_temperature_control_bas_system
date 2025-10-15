#!/bin/bash
# verify_system.sh - Verify the complete BAS distributed system setup

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

echo "🔍 BAS System Verification"
echo "========================="
echo ""

VERIFICATION_PASSED=true

# Check system requirements
print_info "Checking system requirements..."

# Python 3
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    print_status "Python 3: $PYTHON_VERSION"
else
    print_error "Python 3 not found"
    VERIFICATION_PASSED=false
fi

# pip3
if command -v pip3 &> /dev/null; then
    print_status "pip3 found"
else
    print_error "pip3 not found"
    VERIFICATION_PASSED=false
fi

# mpremote
if command -v mpremote &> /dev/null; then
    print_status "mpremote found"
else
    print_warning "mpremote not found (needed for Pico deployment)"
    print_info "Install with: pip3 install mpremote"
fi

echo ""

# Check project structure
print_info "Checking project structure..."

# Essential files
ESSENTIAL_FILES=(
    "pico_client.py"
    "setup.sh"
    "deploy_pico.sh"
    "start_server.sh"
    "server/bas_server.py"
    "server/requirements.txt"
    "server/templates/dashboard.html"
)

for file in "${ESSENTIAL_FILES[@]}"; do
    if [ -f "$file" ]; then
        print_status "Found: $file"
    else
        print_error "Missing: $file"
        VERIFICATION_PASSED=false
    fi
done

echo ""

# Check script permissions
print_info "Checking script permissions..."

SCRIPTS=("setup.sh" "deploy_pico.sh" "start_server.sh")

for script in "${SCRIPTS[@]}"; do
    if [ -x "$script" ]; then
        print_status "Executable: $script"
    else
        print_warning "Not executable: $script"
        print_info "Run: chmod +x $script"
    fi
done

echo ""

# Check pico_client.py size
print_info "Checking Pico client optimization..."

if [ -f "pico_client.py" ]; then
    CLIENT_SIZE=$(wc -c < pico_client.py)
    print_status "pico_client.py size: $CLIENT_SIZE bytes ($(($CLIENT_SIZE/1024)) KB)"
    
    if [ $CLIENT_SIZE -lt 50000 ]; then
        print_status "Client size optimized for Pico W storage"
    else
        print_warning "Client size may be too large for optimal Pico W usage"
    fi
else
    print_error "pico_client.py not found"
    VERIFICATION_PASSED=false
fi

echo ""

# Check server configuration
print_info "Checking server configuration..."

if [ -d "server" ]; then
    cd server
    
    # Check virtual environment
    if [ -d "venv" ]; then
        print_status "Virtual environment exists"
    else
        print_warning "Virtual environment not found"
        print_info "Run: ./setup.sh or cd server && ./setup_server.sh"
    fi
    
    # Check requirements
    if [ -f "requirements.txt" ]; then
        print_status "Requirements file found"
        DEPENDENCIES=$(wc -l < requirements.txt)
        print_status "Dependencies: $DEPENDENCIES packages"
    else
        print_error "requirements.txt not found"
        VERIFICATION_PASSED=false
    fi
    
    cd ..
else
    print_error "Server directory not found"
    VERIFICATION_PASSED=false
fi

echo ""

# Check WiFi configuration
print_info "Checking WiFi configuration..."

if [ -f "pico_client.py" ]; then
    if grep -q "YOUR_WIFI_NETWORK" pico_client.py; then
        print_warning "WiFi credentials not configured"
        print_info "Update WIFI_SSID and WIFI_PASSWORD in pico_client.py"
    else
        print_status "WiFi credentials configured"
    fi
    
    # Check server URL
    if grep -q "192.168.1.100" pico_client.py; then
        print_warning "Server URL may need updating"
        print_info "Current SERVER_URL: $(grep 'SERVER_URL =' pico_client.py)"
    else
        print_status "Server URL configured"
    fi
else
    print_error "pico_client.py not found"
    VERIFICATION_PASSED=false
fi

echo ""

# Network detection test
print_info "Testing network configuration..."

if [[ "$OSTYPE" == "darwin"* ]]; then
    COMPUTER_IP=$(ifconfig | grep -E "inet.*broadcast" | awk '{print $2}' | head -1)
else
    COMPUTER_IP=$(ip route get 8.8.8.8 | grep -oP 'src \K\S+' | head -1)
fi

if [ -n "$COMPUTER_IP" ]; then
    print_status "Computer IP detected: $COMPUTER_IP"
else
    print_warning "Could not detect computer IP address"
fi

echo ""

# Final verification summary
print_info "Verification Summary"
echo "===================="

if [ "$VERIFICATION_PASSED" = true ]; then
    print_status "✅ System verification PASSED"
    echo ""
    print_info "Ready to deploy! Next steps:"
    echo "1. Update WiFi credentials in pico_client.py"
    echo "2. Connect your Pico W via USB"
    echo "3. Run: ./deploy_pico.sh"
    echo "4. Run: ./start_server.sh"
    echo "5. Open: http://localhost:8080"
    echo ""
    print_status "System is ready for deployment! 🎉"
else
    print_error "❌ System verification FAILED"
    echo ""
    print_info "Please fix the issues above before deploying"
    echo "Run ./setup.sh to resolve most issues automatically"
fi
