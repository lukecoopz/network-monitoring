#!/bin/bash
# Install Network Monitoring Tool as a systemd service

set -e

echo "🌐 Network Monitoring Tool - Service Installation"
echo "=================================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Get the current directory (where the script is located)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SERVICE_FILE="$SCRIPT_DIR/network-monitoring.service"
SYSTEMD_DIR="/etc/systemd/system"

# Detect user (try common Pi-hole users)
if id "pi" &>/dev/null; then
    SERVICE_USER="pi"
elif id "pihole" &>/dev/null; then
    SERVICE_USER="pihole"
else
    SERVICE_USER=$(logname 2>/dev/null || echo $SUDO_USER)
    if [ -z "$SERVICE_USER" ]; then
        echo "❌ Could not determine user. Please edit the service file manually."
        exit 1
    fi
fi

echo "📋 Detected user: $SERVICE_USER"
echo "📁 Installation directory: $SCRIPT_DIR"
echo ""

# Check if service file exists
if [ ! -f "$SERVICE_FILE" ]; then
    echo "❌ Service file not found: $SERVICE_FILE"
    exit 1
fi

# Update service file with correct paths
echo "🔧 Configuring service file..."
sed -i.bak "s|/home/pi/network-monitoring|$SCRIPT_DIR|g" "$SERVICE_FILE"
sed -i.bak "s|User=pi|User=$SERVICE_USER|g" "$SERVICE_FILE"
sed -i.bak "s|Group=pi|Group=$SERVICE_USER|g" "$SERVICE_FILE"

# Verify virtual environment exists
if [ ! -f "$SCRIPT_DIR/venv/bin/python3" ]; then
    echo "⚠️  Warning: Virtual environment not found at $SCRIPT_DIR/venv"
    echo "   Please run setup.sh first to create the virtual environment"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Copy service file to systemd directory
echo "📦 Installing service file..."
cp "$SERVICE_FILE" "$SYSTEMD_DIR/network-monitoring.service"

# Reload systemd
echo "🔄 Reloading systemd..."
systemctl daemon-reload

# Enable service
echo "✅ Enabling service..."
systemctl enable network-monitoring.service

echo ""
echo "✅ Service installed successfully!"
echo ""
echo "Service commands:"
echo "  Start:   sudo systemctl start network-monitoring"
echo "  Stop:    sudo systemctl stop network-monitoring"
echo "  Status:  sudo systemctl status network-monitoring"
echo "  Logs:    sudo journalctl -u network-monitoring -f"
echo "  Restart: sudo systemctl restart network-monitoring"
echo ""
echo "The service will start automatically on boot."
echo ""
echo "To start it now, run:"
echo "  sudo systemctl start network-monitoring"

