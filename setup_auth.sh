#!/bin/bash
# BAS Authentication Setup Script

echo "🔐 BAS Authentication Setup"
echo "=========================="

# Check if we're in the right directory
if [ ! -f "server/bas_server.py" ]; then
    echo "❌ Please run this script from the BAS System Project root directory"
    exit 1
fi

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip3."
    exit 1
fi

echo "✅ pip3 found"

# Create virtual environment if it doesn't exist
if [ ! -d "server/venv" ]; then
    echo "📦 Creating virtual environment..."
    cd server
    python3 -m venv venv
    cd ..
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
cd server
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📥 Installing Python dependencies..."
pip install -r requirements.txt

# Run authentication setup
echo "🔧 Setting up authentication system..."
python ../scripts/setup_auth.py

# Check if setup was successful
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Authentication setup completed successfully!"
    echo ""
    echo "📋 Next steps:"
    echo "1. Update Twilio credentials in config/secrets.json"
    echo "2. Change default admin password using:"
    echo "   python scripts/auth_admin.py reset-password admin <new_password>"
    echo "3. Create additional users as needed:"
    echo "   python scripts/auth_admin.py create-user <username> <password> <phone> --role <role>"
    echo "4. Start the server:"
    echo "   cd server && source venv/bin/activate && python bas_server.py"
    echo ""
    echo "🌐 The dashboard will be available at: http://localhost:8080"
    echo "🔐 Login page: http://localhost:8080/auth/login"
    echo ""
    echo "⚠️  IMPORTANT: Change the default admin credentials immediately!"
    echo "   Default: admin / Admin123!@# / +1234567890"
else
    echo "❌ Authentication setup failed. Please check the error messages above."
    exit 1
fi

cd ..
