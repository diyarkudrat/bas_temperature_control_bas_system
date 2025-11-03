#!/bin/bash
# verify_system.sh - Verify the complete BAS distributed system setup

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LEGACY_ROOT="$REPO_ROOT/legacy"
PICO_CLIENT_PATH="$LEGACY_ROOT/pico_client.py"
LEGACY_SCRIPTS="$LEGACY_ROOT/scripts"

cd "$REPO_ROOT"

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
    "legacy/pico_client.py"
    "legacy/setup.sh"
    "server/bas_server.py"
    "apps/api/main.py"
    "apps/api/requirements.txt"
    "apps/api/templates/dashboard.html"
    "legacy/scripts/start_bas.sh"
    "legacy/scripts/start_hardware.sh"
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

SCRIPTS=("legacy/setup.sh" "legacy/scripts/start_bas.sh" "legacy/scripts/start_hardware.sh")

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

if [ -f "$PICO_CLIENT_PATH" ]; then
    CLIENT_SIZE=$(wc -c < "$PICO_CLIENT_PATH")
    print_status "pico_client.py size: $CLIENT_SIZE bytes ($(($CLIENT_SIZE/1024)) KB)"
    
    if [ $CLIENT_SIZE -lt 50000 ]; then
        print_status "Client size optimized for Pico W storage"
    else
        print_warning "Client size may be too large for optimal Pico W usage"
    fi
else
    print_error "pico_client.py not found at $PICO_CLIENT_PATH"
    VERIFICATION_PASSED=false
fi

echo ""

# Check API configuration
print_info "Checking API configuration..."

if [ -f "apps/api/requirements.txt" ]; then
    print_status "API requirements found (apps/api/requirements.txt)"
    DEPENDENCIES=$(wc -l < apps/api/requirements.txt)
    print_status "Dependencies: $DEPENDENCIES packages"
else
    print_error "apps/api/requirements.txt not found"
    VERIFICATION_PASSED=false
fi

echo ""

# Check WiFi configuration
print_info "Checking WiFi configuration..."

if [ -f "$PICO_CLIENT_PATH" ]; then
    if grep -q "YOUR_WIFI_NETWORK" "$PICO_CLIENT_PATH"; then
        print_warning "WiFi credentials not configured"
        print_info "Update WIFI_SSID and WIFI_PASSWORD in $PICO_CLIENT_PATH"
    else
        print_status "WiFi credentials configured"
    fi
    
    # Check server URL
    if grep -q "192.168.1.100" "$PICO_CLIENT_PATH"; then
        print_warning "Server URL may need updating"
        print_info "Current SERVER_URL: $(grep 'SERVER_URL =' "$PICO_CLIENT_PATH")"
    else
        print_status "Server URL configured"
    fi
else
    print_error "pico_client.py not found at $PICO_CLIENT_PATH"
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
    echo "1. Update WiFi credentials in legacy/pico_client.py"
    echo "2. Connect your Pico W via USB"
    echo "3. Run: ./legacy/scripts/start_hardware.sh --deploy-only"
    echo "4. Run: ./legacy/scripts/start_bas.sh --server-only"
    echo "5. Open: http://localhost:8080"
    echo ""
    print_status "System is ready for deployment! 🎉"
else
    print_error "❌ System verification FAILED"
    echo ""
    print_info "Please fix the issues above before deploying"
    echo "Run ./legacy/setup.sh to resolve most issues automatically"
fi
