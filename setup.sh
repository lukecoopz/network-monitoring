#!/bin/bash
# Setup script for Network Monitoring Tool

echo "🌐 Network Monitoring Tool - Setup"
echo "=================================="
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"
echo ""

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv

if [ $? -ne 0 ]; then
    echo "❌ Failed to create virtual environment"
    exit 1
fi

echo "✅ Virtual environment created"
echo ""

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
python3 -m pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies..."
python3 -m pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "To run the application:"
echo "  1. Activate the virtual environment: source venv/bin/activate"
echo "  2. Run: python3 app.py (or sudo python3 app.py for packet capture)"
echo ""
echo "Note:"
echo "  - Install nmap if not already installed: brew install nmap (macOS) or sudo apt-get install nmap (Linux)"
echo "  - If running on Pi-hole, the tool will automatically detect and use Pi-hole's query log"
echo "  - Web interface will be available at http://localhost:5001"

