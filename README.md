# Network Monitoring Tool

A simplified network monitoring tool similar to Ntopng that tracks devices on your network and monitors top sites visited. Features a beautiful Dracula-themed web interface with interactive pie charts and detailed site statistics.

## Features

- **Device Discovery**: Automatically scans and discovers devices on your local network
- **Site Tracking**: Monitors DNS queries to track top sites visited by devices
- **Interactive Dashboard**: 
  - Pie charts showing top sites visited
  - Detailed tables with visit counts, percentages, and timestamps
  - Filter by individual devices
  - Global search for devices and sites
  - Real-time statistics
- **Pi-hole Integration**: Automatically detects and uses Pi-hole's query log (recommended)
- **Service Support**: Can run as a systemd service for automatic startup
- **Dracula Theme**: Beautiful dark theme UI

## Requirements

- Python 3.7+
- Root/Administrator privileges (for packet capture, or if running on Pi-hole)
- Network access to scan local network
- **macOS/Linux**: nmap installed (`brew install nmap` or `sudo apt-get install nmap`)

## Installation

### Quick Setup

1. Clone or download this repository

2. Run the setup script:
```bash
chmod +x setup.sh
./setup.sh
```

### Manual Setup

1. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install system dependencies:
   - **macOS**: `brew install nmap`
   - **Linux**: `sudo apt-get install nmap` (Debian/Ubuntu) or `sudo yum install nmap` (RHEL/CentOS)

## Usage

### Running on Pi-hole Server (Recommended)

**This tool works perfectly on Pi-hole servers!** Since Pi-hole acts as the DNS server for your network, it sees ALL DNS queries from all devices. The tool will automatically detect Pi-hole and read queries directly from Pi-hole's database.

#### Option 1: Run as a Service (Recommended)

Run as a systemd service that starts automatically on boot and runs in the background:

```bash
# Install the service
sudo chmod +x install-service.sh
sudo ./install-service.sh

# Start the service
sudo systemctl start network-monitoring

# Check status
sudo systemctl status network-monitoring

# View logs
sudo journalctl -u network-monitoring -f
```

**Service Management:**
```bash
# Start/Stop/Restart
sudo systemctl start network-monitoring
sudo systemctl stop network-monitoring
sudo systemctl restart network-monitoring

# Enable/Disable auto-start on boot
sudo systemctl enable network-monitoring
sudo systemctl disable network-monitoring

# View logs
sudo journalctl -u network-monitoring -f
```

See `PIHOLE_SERVICE_SETUP.md` for detailed service setup and troubleshooting.

#### Option 2: Manual Run

```bash
# Activate virtual environment
source venv/bin/activate

# Run (may need sudo for network scanning)
python3 app.py
```

**Benefits of running on Pi-hole:**
- ✅ Sees ALL DNS queries from ALL devices
- ✅ More reliable than packet capture
- ✅ No network topology limitations
- ✅ Lower resource usage
- ✅ Can run as a service for automatic startup

### Running on Regular Device

```bash
# Activate virtual environment
source venv/bin/activate  # if using venv

# Run with sudo (required for packet capture)
sudo python3 app.py
```

**Note**: If you're using a virtual environment with sudo, use:
```bash
sudo venv/bin/python3 app.py
```

#### Windows (as Administrator)

```bash
python app.py
```

The web interface will be available at: `http://localhost:5001`

**Note**: If port 5001 is in use, change it in `app.py` (line 216).

## How It Works

1. **Network Scanning**: Scans your local network every minute to discover devices
2. **DNS Query Collection**: 
   - **On Pi-hole**: Automatically reads queries from `/etc/pihole/pihole-FTL.db` (recommended)
   - **Otherwise**: Captures DNS queries via packet capture (port 53)
3. **Data Storage**: Stores device and DNS query data in a SQLite database
4. **Web Interface**: Real-time dashboard with:
   - All discovered devices
   - Top sites visited across all devices
   - Per-device site filtering
   - Global search functionality
   - Timestamps and filtering options

## Network Limitations

### On Switched Networks

On typical switched networks, packet capture can only see:
- Traffic sent to/from your device
- Broadcast traffic

**Solutions to see all traffic:**
- **Pi-hole Server** (Best): Run the tool on your Pi-hole server - it sees all DNS queries
- **Port Mirroring/SPAN**: Configure your managed switch to mirror traffic
- **Network Tap**: Use a hardware network tap
- **Router/Gateway**: Run the tool on a device that routes network traffic

The tool automatically uses Pi-hole's query log when available, which bypasses these limitations.

## Troubleshooting

### Permission Errors

- Make sure you're running with `sudo` (macOS/Linux) or as Administrator (Windows)
- On macOS, grant Terminal/IDE network permissions in System Preferences
- For Pi-hole database access, ensure your user has read permissions

### No Devices Found

- Network scanner may take a minute to discover devices
- Ensure you're on a network with other devices
- Some networks may block ARP scanning

### No Sites Tracked

- DNS queries are only captured when devices make DNS requests
- Ensure devices are actively browsing the web
- On Pi-hole: Check that Pi-hole is running and accessible
- Check service logs: `sudo journalctl -u network-monitoring -n 50`

### Service Issues

If running as a service and having problems:

1. **Check service status**:
   ```bash
   sudo systemctl status network-monitoring
   ```

2. **View logs**:
   ```bash
   sudo journalctl -u network-monitoring -f
   ```

3. **Verify paths in service file**:
   ```bash
   sudo systemctl cat network-monitoring
   ```

4. **Test manual run**:
   ```bash
   cd /path/to/network-monitoring
   source venv/bin/activate
   python3 app.py
   ```

See `PIHOLE_SERVICE_SETUP.md` for detailed troubleshooting.

### Port Already in Use

Change the port in `app.py`:
```python
app.run(host='0.0.0.0', port=5001, debug=True)
```

Then restart the service:
```bash
sudo systemctl restart network-monitoring
```

## Technical Details

- **Backend**: Flask (Python)
- **Database**: SQLite
- **Network Scanning**: python-nmap
- **Packet Capture**: Scapy
- **Pi-hole Integration**: Direct database reading
- **Frontend**: Vanilla JavaScript with Chart.js
- **Theme**: Dracula color scheme
- **Service**: Systemd service support

## Project Structure

```
network-monitoring/
├── app.py                      # Main Flask application
├── network_scanner.py          # Device discovery
├── packet_capture.py           # DNS packet capture
├── pihole_reader.py            # Pi-hole query log reader
├── requirements.txt             # Python dependencies
├── setup.sh                    # Setup script
├── install-service.sh          # Service installation script
├── network-monitoring.service  # Systemd service file
├── static/                     # Web interface
│   ├── index.html
│   ├── style.css
│   └── app.js
├── README.md                   # This file
└── PIHOLE_SERVICE_SETUP.md     # Service setup guide
```

## Security Note

This tool monitors network traffic on your local network. Only use it on networks you own or have permission to monitor. Respect privacy and applicable laws regarding network monitoring.

## License

This project is provided as-is for educational and monitoring purposes.
