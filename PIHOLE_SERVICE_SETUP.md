# Running Network Monitoring Tool as a Service on Pi-hole

This guide will help you set up the Network Monitoring Tool to run as a systemd service on your Pi-hole server, so it starts automatically on boot and can be managed like other system services.

## Prerequisites

- Pi-hole server (Raspberry Pi or Linux server)
- Network Monitoring Tool installed and working
- Virtual environment set up
- Root/sudo access

## Installation Steps

### 1. Install the Service

Run the installation script as root:

```bash
cd /path/to/network-monitoring
sudo chmod +x install-service.sh
sudo ./install-service.sh
```

The script will:
- Detect your user account
- Configure the service file with correct paths
- Install it to systemd
- Enable it to start on boot

### 2. Start the Service

```bash
sudo systemctl start network-monitoring
```

### 3. Verify It's Running

```bash
sudo systemctl status network-monitoring
```

You should see "active (running)" in green.

### 4. Check the Logs

```bash
# View live logs
sudo journalctl -u network-monitoring -f

# View recent logs
sudo journalctl -u network-monitoring -n 50
```

## Service Management Commands

```bash
# Start the service
sudo systemctl start network-monitoring

# Stop the service
sudo systemctl stop network-monitoring

# Restart the service
sudo systemctl restart network-monitoring

# Check status
sudo systemctl status network-monitoring

# Enable auto-start on boot
sudo systemctl enable network-monitoring

# Disable auto-start on boot
sudo systemctl disable network-monitoring

# View logs
sudo journalctl -u network-monitoring -f
```

## Manual Service File Installation

If the script doesn't work, you can install manually:

1. **Edit the service file** to match your setup:
   ```bash
   nano network-monitoring.service
   ```
   
   Update these lines:
   - `User=pi` → Your username
   - `Group=pi` → Your group
   - `/home/pi/network-monitoring` → Your installation path

2. **Copy to systemd directory**:
   ```bash
   sudo cp network-monitoring.service /etc/systemd/system/
   ```

3. **Reload systemd**:
   ```bash
   sudo systemctl daemon-reload
   ```

4. **Enable and start**:
   ```bash
   sudo systemctl enable network-monitoring
   sudo systemctl start network-monitoring
   ```

## Configuration

### Changing the Port

If you need to change the port (default: 5001), edit `app.py`:

```python
app.run(host='0.0.0.0', port=5001, debug=True)
```

Then restart the service:
```bash
sudo systemctl restart network-monitoring
```

### Running on a Different Interface

The service will automatically detect Pi-hole and use its query log. If you need to bind to a specific interface, modify `app.py`:

```python
app.run(host='0.0.0.0', port=5001, debug=False)  # Set debug=False for production
```

## Troubleshooting

### Service Won't Start

1. **Check the logs**:
   ```bash
   sudo journalctl -u network-monitoring -n 100
   ```

2. **Check file permissions**:
   ```bash
   ls -la /path/to/network-monitoring
   ```

3. **Verify virtual environment**:
   ```bash
   /path/to/network-monitoring/venv/bin/python3 --version
   ```

4. **Test manual run**:
   ```bash
   cd /path/to/network-monitoring
   source venv/bin/activate
   python3 app.py
   ```

### Permission Issues

If you see permission errors:

1. **Check Pi-hole database access**:
   ```bash
   ls -la /etc/pihole/pihole-FTL.db
   ```

2. **Add user to pihole group** (if needed):
   ```bash
   sudo usermod -a -G pihole $USER
   ```

3. **Check network scanning permissions** (may need sudo for nmap):
   - The service runs as a regular user by default
   - Network scanning may be limited without root
   - Consider running network scanning separately or adjusting permissions

### Port Already in Use

If port 5001 is in use:

1. **Find what's using it**:
   ```bash
   sudo netstat -tulpn | grep 5001
   ```

2. **Change the port** in `app.py` and restart the service

### Service Keeps Restarting

Check the logs to see why it's crashing:
```bash
sudo journalctl -u network-monitoring -n 100 --no-pager
```

Common issues:
- Missing dependencies
- Database permission issues
- Port conflicts

## Accessing the Web Interface

Once the service is running, access the web interface at:

```
http://your-pi-hole-ip:5001
```

Or if running locally:
```
http://localhost:5001
```

## Updating the Service

When you update the code:

1. **Pull/update your code**
2. **Restart the service**:
   ```bash
   sudo systemctl restart network-monitoring
   ```

## Uninstalling the Service

```bash
sudo systemctl stop network-monitoring
sudo systemctl disable network-monitoring
sudo rm /etc/systemd/system/network-monitoring.service
sudo systemctl daemon-reload
```

## Integration with Pi-hole

The service is configured to:
- Start after network and Pi-hole FTL service
- Automatically detect Pi-hole's query log
- Work seamlessly with Pi-hole's DNS queries

The tool will automatically use Pi-hole's database when available, so you don't need special permissions for packet capture.

