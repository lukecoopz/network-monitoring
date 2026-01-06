# Fixing Service Issues on Your Server

## Problem: ModuleNotFoundError: No module named 'flask'

This error means the service is using system Python instead of your virtual environment's Python.

## Quick Fix Steps

### 1. Verify Virtual Environment Exists and Has Packages

SSH into your server and run:

```bash
cd /home/luke/Documents/network-monitoring

# Check if venv exists
ls -la venv/bin/python3

# Activate and check packages
source venv/bin/activate
pip list | grep flask

# If flask is not installed, install it:
pip install -r requirements.txt
```

### 2. Check Current Service Configuration

```bash
sudo systemctl cat network-monitoring.service
```

Look for the `ExecStart` line - it should point to your venv's Python:
```
ExecStart=/home/luke/Documents/network-monitoring/venv/bin/python3 /home/luke/Documents/network-monitoring/app.py
```

### 3. Fix the Service File

Edit the service file:

```bash
sudo nano /etc/systemd/system/network-monitoring.service
```

Make sure it looks like this (update paths for your setup):

```ini
[Unit]
Description=Network Monitoring Tool
After=network.target pihole-FTL.service
Wants=pihole-FTL.service

[Service]
Type=simple
User=luke
Group=luke
WorkingDirectory=/home/luke/Documents/network-monitoring
Environment="PATH=/home/luke/Documents/network-monitoring/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="VIRTUAL_ENV=/home/luke/Documents/network-monitoring/venv"
ExecStart=/home/luke/Documents/network-monitoring/venv/bin/python3 /home/luke/Documents/network-monitoring/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Important**: Replace:
- `User=luke` with your actual username
- `Group=luke` with your actual group
- `/home/luke/Documents/network-monitoring` with your actual installation path

### 4. Reload and Restart

```bash
# Reload systemd
sudo systemctl daemon-reload

# Restart the service
sudo systemctl restart network-monitoring

# Check status
sudo systemctl status network-monitoring
```

### 5. Verify It's Working

```bash
# Check logs
sudo journalctl -u network-monitoring -f

# You should see:
# "Network Monitoring Tool starting..."
# "Access the web interface at http://localhost:5000"
```

## Alternative: Re-run Installation Script

If the above doesn't work, re-run the installation script from your server:

```bash
cd /home/luke/Documents/network-monitoring
sudo ./install-service.sh
```

The script should automatically detect your user and paths.

## Verify Virtual Environment

Make sure your virtual environment has all packages:

```bash
cd /home/luke/Documents/network-monitoring
source venv/bin/activate
pip install -r requirements.txt
```

## Test Manual Run

Before fixing the service, test that it works manually:

```bash
cd /home/luke/Documents/network-monitoring
source venv/bin/activate
python3 app.py
```

If this works, the service should work too once configured correctly.

