#!/bin/bash
# setup.sh - Complete BAS System Setup
# This script sets up the entire distributed BAS system

set -euo pipefail

echo "🏠 BAS Temperature Controller - Complete Setup"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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

# Check if running on macOS or Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="Linux"
else
    print_error "Unsupported operating system: $OSTYPE"
    print_info "This script supports macOS and Linux only."
    exit 1
fi

print_info "Detected platform: $PLATFORM"
echo ""

# Check for required tools
print_info "Checking system requirements..."

# Check Python 3
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed"
    print_info "Please install Python 3.7 or higher:"
    if [[ "$PLATFORM" == "macOS" ]]; then
        print_info "  brew install python3"
    else
        print_info "  sudo apt-get install python3 python3-pip"
    fi
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
print_status "Python 3 found: $PYTHON_VERSION"

# Check pip3
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is not installed"
    print_info "Please install pip3"
    exit 1
fi
print_status "pip3 found"

# Check mpremote (for Pico W deployment)
if ! command -v mpremote &> /dev/null; then
    print_warning "mpremote not found - needed for Pico W deployment"
    print_info "Installing mpremote..."
    pip3 install mpremote
    if [ $? -eq 0 ]; then
        print_status "mpremote installed successfully"
    else
        print_error "Failed to install mpremote"
        print_info "You can install it manually with: pip3 install mpremote"
    fi
else
    print_status "mpremote found"
fi

echo ""
print_info "Setting up server components..."

# Setup server
if [ -d "server" ]; then
    cd server
    
    # Run server setup script
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
    
    cd ..
else
    print_error "Server directory not found"
    exit 1
fi

echo ""
print_info "Setting up authentication system..."

# Setup authentication directly
if [ -f "scripts/setup_auth.py" ]; then
    print_info "Configuring authentication system..."
    
    # Check if virtual environment exists
    if [ ! -d "server/venv" ]; then
        print_error "Server virtual environment not found"
        print_info "Please run server setup first"
        exit 1
    fi
    
    # Activate virtual environment and run auth setup
    cd server
    source venv/bin/activate
    
    # Run authentication setup
    python ../scripts/setup_auth.py
    AUTH_SETUP_RESULT=$?
    
    cd ..
    
    if [ $AUTH_SETUP_RESULT -eq 0 ]; then
        print_status "Authentication setup completed"
    else
        print_error "Authentication setup failed"
        exit 1
    fi
else
    print_error "Authentication setup script not found"
    exit 1
fi

echo ""
print_info "Auto-detecting network configuration..."

# Auto-detect computer IP address
if [[ "$PLATFORM" == "macOS" ]]; then
    # macOS IP detection
    COMPUTER_IP=$(ifconfig | grep -E "inet.*broadcast" | awk '{print $2}' | head -1)
    if [ -z "$COMPUTER_IP" ]; then
        # Fallback method
        COMPUTER_IP=$(route get default | grep interface | awk '{print $2}' | xargs ifconfig | grep "inet " | awk '{print $2}' | head -1)
    fi
else
    # Linux IP detection
    COMPUTER_IP=$(ip route get 8.8.8.8 | grep -oP 'src \K\S+' | head -1)
    if [ -z "$COMPUTER_IP" ]; then
        # Fallback method
        COMPUTER_IP=$(hostname -I | awk '{print $1}')
    fi
fi

if [ -n "$COMPUTER_IP" ]; then
    print_status "Computer IP address detected: $COMPUTER_IP"
    
    # Update pico_client.py with detected IP
    if [ -f "pico_client.py" ]; then
        print_info "Updating pico_client.py with detected IP address..."
        
        # Create backup
        cp pico_client.py pico_client.py.backup
        
        # Update SERVER_URL
        sed -i.tmp "s|SERVER_URL = \"http://[^\"]*\"|SERVER_URL = \"http://$COMPUTER_IP:8080\"|g" pico_client.py
        rm -f pico_client.py.tmp
        
        print_status "pico_client.py updated with IP: $COMPUTER_IP"
        print_warning "Please manually update WiFi credentials in pico_client.py"
    else
        print_warning "pico_client.py not found - please update SERVER_URL manually"
    fi
else
    print_warning "Could not auto-detect IP address"
    print_info "Please manually update SERVER_URL in pico_client.py"
fi

echo ""
print_info "Making scripts executable..."

# Make all shell scripts executable
chmod +x deploy_pico.sh 2>/dev/null || true
chmod +x start_server.sh 2>/dev/null || true
chmod +x scripts/*.sh 2>/dev/null || true

print_status "Scripts made executable"

echo ""
print_info "Checking hardware configuration..."

# Check if pico_client.py has WiFi credentials configured
if [ -f "pico_client.py" ]; then
    if grep -q "YOUR_WIFI_NETWORK" pico_client.py; then
        print_warning "WiFi credentials not configured in pico_client.py"
        print_info "Please update WIFI_SSID and WIFI_PASSWORD before deploying"
    else
        print_status "WiFi credentials appear to be configured"
    fi
else
    print_error "pico_client.py not found"
fi

echo ""
print_info "Setup Summary"
echo "==============="
print_status "✅ System requirements checked"
print_status "✅ Server environment configured"
print_status "✅ Authentication system configured"
print_status "✅ Network configuration detected"
print_status "✅ Scripts prepared for execution"

echo ""
print_info "Next Steps:"
echo "1. Update WiFi credentials in pico_client.py:"
echo "   WIFI_SSID = \"Your Network Name\""
echo "   WIFI_PASSWORD = \"Your Password\""
echo ""
echo "2. Configure Twilio credentials in config/secrets.json:"
echo "   Add your Twilio account_sid, auth_token, and from_number"
echo ""
echo "3. Change default admin password:"
echo "   python scripts/auth_admin.py reset-password admin <new_password>"
echo ""
echo "4. Connect your Pico W via USB"
echo ""
echo "5. Deploy to Pico W:"
echo "   ./deploy_pico.sh"
echo ""
echo "6. Start the server:"
echo "   ./start_server.sh"
echo ""
echo "7. Open dashboard:"
echo "   http://localhost:8080"
echo "   Login: http://localhost:8080/auth/login"
echo ""

print_info "Hardware Connections:"
echo "• DS18B20 Sensor → GP4 (with 4.7kΩ pull-up to 3.3V)"
echo "• Cooling Relay → GP15"
echo "• Heating Relay → GP14"
echo ""

print_status "Setup completed successfully! 🎉"