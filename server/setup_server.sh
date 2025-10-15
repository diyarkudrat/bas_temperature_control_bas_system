#!/bin/bash
# BAS Server Setup Script

echo "🏠 BAS Server Setup"
echo "==================="

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
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📥 Installing Python dependencies..."
pip install -r requirements.txt

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 To start the server:"
echo "   1. Activate the virtual environment: source venv/bin/activate"
echo "   2. Run the server: python bas_server.py"
echo ""
echo "🌐 The dashboard will be available at: http://localhost:8080"
echo "📱 Make sure to update the SERVER_URL in pico_client.py with your computer's IP address"
echo ""
echo "💡 To find your computer's IP address:"
echo "   - Mac/Linux: ifconfig | grep 'inet '"
echo "   - Windows: ipconfig"
