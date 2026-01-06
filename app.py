#!/usr/bin/env python3
"""
Network Monitoring Tool - Backend API
Collects devices on network and tracks top sites visited
"""

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
import threading
import time
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
import json
import os

from network_scanner import NetworkScanner
from packet_capture import PacketCapture
from pihole_reader import PiholeReader

app = Flask(__name__, static_folder='static')
CORS(app)

# Initialize components
scanner = NetworkScanner()
capture = PacketCapture()
pihole = PiholeReader()

# Database setup
DB_FILE = 'network_monitoring.db'

def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Devices table
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, 
                  first_seen TEXT, last_seen TEXT, vendor TEXT)''')
    
    # DNS queries table
    c.execute('''CREATE TABLE IF NOT EXISTS dns_queries
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  device_mac TEXT, device_ip TEXT, domain TEXT,
                  timestamp TEXT, count INTEGER,
                  FOREIGN KEY (device_mac) REFERENCES devices(mac))''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Serve main page"""
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    return send_from_directory('static', path)

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get all discovered devices"""
    conn = get_db_connection()
    devices = conn.execute(
        'SELECT * FROM devices ORDER BY last_seen DESC'
    ).fetchall()
    conn.close()
    
    return jsonify([dict(device) for device in devices])

@app.route('/api/devices/<device_mac>/sites', methods=['GET'])
def get_device_sites(device_mac):
    """Get top sites for a specific device"""
    conn = get_db_connection()
    
    # Get sites for device with latest timestamp
    sites = conn.execute(
        '''SELECT domain, SUM(count) as total_count, MAX(timestamp) as last_visited
           FROM dns_queries
           WHERE device_mac = ?
           GROUP BY domain
           ORDER BY total_count DESC
           LIMIT 100''',
        (device_mac,)
    ).fetchall()
    
    conn.close()
    
    return jsonify([dict(site) for site in sites])

@app.route('/api/sites/all', methods=['GET'])
def get_all_sites():
    """Get top sites across all devices"""
    conn = get_db_connection()
    
    sites = conn.execute(
        '''SELECT domain, SUM(count) as total_count, MAX(timestamp) as last_visited
           FROM dns_queries
           GROUP BY domain
           ORDER BY total_count DESC
           LIMIT 100'''
    ).fetchall()
    
    conn.close()
    
    return jsonify([dict(site) for site in sites])

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall statistics"""
    conn = get_db_connection()
    
    device_count = conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
    total_queries = conn.execute('SELECT SUM(count) FROM dns_queries').fetchone()[0] or 0
    unique_domains = conn.execute('SELECT COUNT(DISTINCT domain) FROM dns_queries').fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'device_count': device_count,
        'total_queries': total_queries,
        'unique_domains': unique_domains
    })

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    """Manually trigger a network scan"""
    try:
        # Sync devices from Pi-hole first (most reliable)
        if pihole.pihole_db and pihole.pihole_db.endswith('.db'):
            print("Manual scan: Syncing devices from Pi-hole...")
            pihole.sync_devices_from_pihole()
        
        # Then do network scan
        print("Manual scan: Running network scan...")
        scanner.scan_network()
        
        return jsonify({'status': 'success', 'message': 'Network scan and Pi-hole sync triggered'})
    except Exception as e:
        print(f"Error in trigger_scan: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get recent application logs"""
    try:
        import subprocess
        import os
        
        # Try to get logs from journalctl if running as service
        try:
            result = subprocess.run(
                ['journalctl', '-u', 'network-monitoring', '-n', '100', '--no-pager'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                return jsonify({
                    'status': 'success',
                    'logs': result.stdout,
                    'source': 'systemd'
                })
        except:
            pass
        
        # Fallback: return a message about checking logs
        return jsonify({
            'status': 'info',
            'logs': 'Logs are available via: sudo journalctl -u network-monitoring -f\n\nOr check the console output if running manually.',
            'source': 'info'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'logs': f'Error getting logs: {str(e)}'}), 500

@app.route('/api/search', methods=['GET'])
def search():
    """Search for devices and sites"""
    query = request.args.get('q', '').strip().lower()
    
    if not query or len(query) < 2:
        return jsonify({
            'devices': [],
            'sites': []
        })
    
    conn = get_db_connection()
    results = {'devices': [], 'sites': []}
    
    # Search devices
    devices = conn.execute(
        '''SELECT * FROM devices 
           WHERE LOWER(hostname) LIKE ? 
           OR LOWER(ip) LIKE ? 
           OR LOWER(mac) LIKE ? 
           OR LOWER(vendor) LIKE ?
           ORDER BY last_seen DESC
           LIMIT 20''',
        (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%')
    ).fetchall()
    results['devices'] = [dict(device) for device in devices]
    
    # Search sites
    sites = conn.execute(
        '''SELECT domain, SUM(count) as total_count, MAX(timestamp) as last_visited
           FROM dns_queries
           WHERE LOWER(domain) LIKE ?
           GROUP BY domain
           ORDER BY total_count DESC
           LIMIT 20''',
        (f'%{query}%',)
    ).fetchall()
    results['sites'] = [dict(site) for site in sites]
    
    conn.close()
    
    return jsonify(results)

def background_scanner():
    """Background thread for network scanning"""
    while True:
        try:
            scanner.scan_network()
            time.sleep(60)  # Scan every minute
        except Exception as e:
            print(f"Scanner error: {e}")
            time.sleep(60)

def background_capture():
    """Background thread for packet capture or Pi-hole reading"""
    # Try Pi-hole first (if available, it's more reliable)
    if pihole.read_queries():
        # Pi-hole reading is active, don't use packet capture
        print("Using Pi-hole query log. Packet capture not needed.")
        return
    
    # Fall back to packet capture if Pi-hole is not available
    while True:
        try:
            capture.capture_packets()
        except Exception as e:
            print(f"Capture error: {e}")
            time.sleep(5)

if __name__ == '__main__':
    init_db()
    
    # Start background threads
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    capture_thread = threading.Thread(target=background_capture, daemon=True)
    
    scanner_thread.start()
    capture_thread.start()
    
    print("Network Monitoring Tool starting...")
    
    # Configure host and port here
    HOST = '0.0.0.0'  # '0.0.0.0' = accessible from all interfaces, '127.0.0.1' = localhost only
    PORT = 5000        # Change this to use a different port
    
    print(f"Access the web interface at http://localhost:{PORT}")
    print(f"Or from other devices: http://<your-ip>:{PORT}")
    print("Note: Packet capture requires root/admin privileges")
    
    # Disable debug mode when running as a service (check if running in systemd)
    import os
    is_service = os.getenv('SYSTEMD_SERVICE', False) or os.path.exists('/.dockerenv') or os.getppid() == 1
    debug_mode = not is_service
    
    app.run(host=HOST, port=PORT, debug=debug_mode)

