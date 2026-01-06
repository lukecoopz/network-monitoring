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
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
    c = conn.cursor()
    
    # Enable WAL mode for better concurrency
    c.execute('PRAGMA journal_mode=WAL')
    
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

def get_db_connection(max_retries=5):
    """Get database connection with retry logic"""
    retry_delay = 0.1
    for attempt in range(max_retries):
        try:
            conn = sqlite3.connect(DB_FILE, timeout=10.0)
            conn.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrency
            conn.execute('PRAGMA journal_mode=WAL')
            return conn
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                time.sleep(retry_delay)
                retry_delay *= 1.5
                continue
            else:
                raise
    raise sqlite3.OperationalError("Failed to connect to database after retries")

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
    try:
        conn = get_db_connection()
        devices = conn.execute(
            'SELECT * FROM devices ORDER BY last_seen DESC'
        ).fetchall()
        conn.close()
        return jsonify([dict(device) for device in devices])
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e).lower():
            return jsonify({'error': 'Database temporarily locked, please try again'}), 503
        raise

@app.route('/api/devices/<device_mac>/sites', methods=['GET'])
def get_device_sites(device_mac):
    """Get top sites for a specific device"""
    try:
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
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e).lower():
            return jsonify({'error': 'Database temporarily locked, please try again'}), 503
        raise

@app.route('/api/sites/all', methods=['GET'])
def get_all_sites():
    """Get top sites across all devices"""
    try:
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
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e).lower():
            return jsonify({'error': 'Database temporarily locked, please try again'}), 503
        raise

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall statistics"""
    try:
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
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e).lower():
            return jsonify({'error': 'Database temporarily locked, please try again'}), 503
        raise

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

@app.route('/api/debug/pihole', methods=['GET'])
def debug_pihole():
    """Debug endpoint to check Pi-hole status"""
    try:
        debug_info = {
            'pihole_detected': pihole.pihole_db is not None,
            'pihole_path': pihole.pihole_db,
            'reading': pihole.reading,
            'last_timestamp': pihole.last_timestamp,
            'cached_queries': len(pihole.query_cache) if pihole.query_cache else 0,
            'cached_query_count': sum(sum(domains.values()) for domains in pihole.query_cache.values()) if pihole.query_cache else 0
        }
        
        # Check monitoring database
        try:
            conn = get_db_connection()
            total_queries = conn.execute('SELECT COUNT(*) FROM dns_queries').fetchone()[0]
            unique_domains = conn.execute('SELECT COUNT(DISTINCT domain) FROM dns_queries').fetchone()[0]
            conn.close()
            debug_info['monitoring_db_queries'] = total_queries
            debug_info['monitoring_db_domains'] = unique_domains
        except sqlite3.OperationalError:
            debug_info['monitoring_db_queries'] = 'locked'
            debug_info['monitoring_db_domains'] = 'locked'
        
        # Try to get some stats from Pi-hole database
        if pihole.pihole_db and pihole.pihole_db.endswith('.db'):
            try:
                import sqlite3
                conn = sqlite3.connect(pihole.pihole_db, timeout=2.0)
                c = conn.cursor()
                
                # Get total queries count
                c.execute("SELECT COUNT(*) FROM queries WHERE timestamp > ?", (int(time.time()) - 86400,))
                recent_queries = c.fetchone()[0]
                debug_info['pihole_recent_queries_24h'] = recent_queries
                
                # Get unique clients
                c.execute("SELECT COUNT(DISTINCT client) FROM queries WHERE client != '' AND client IS NOT NULL")
                unique_clients = c.fetchone()[0]
                debug_info['pihole_unique_clients'] = unique_clients
                
                # Get unique domains
                c.execute("SELECT COUNT(DISTINCT domain) FROM queries WHERE domain != '' AND domain IS NOT NULL AND timestamp > ?", (int(time.time()) - 86400,))
                unique_domains = c.fetchone()[0]
                debug_info['pihole_unique_domains_24h'] = unique_domains
                
                # Get sample of recent queries
                c.execute("SELECT domain, client, timestamp FROM queries WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 10", (int(time.time()) - 3600,))
                sample_queries = c.fetchall()
                debug_info['sample_recent_queries'] = [{'domain': q[0], 'client': q[1], 'timestamp': q[2]} for q in sample_queries]
                
                conn.close()
            except Exception as e:
                debug_info['pihole_db_error'] = str(e)
                import traceback
                debug_info['pihole_db_traceback'] = traceback.format_exc()
        
        return jsonify(debug_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/force-sync', methods=['POST'])
def force_sync():
    """Force sync all queries from Pi-hole database"""
    try:
        if not pihole.pihole_db or not pihole.pihole_db.endswith('.db'):
            return jsonify({'status': 'error', 'message': 'Pi-hole not detected'}), 400
        
        # Sync all queries directly from database
        print("Force sync: Syncing all queries from Pi-hole database...")
        success = pihole.sync_all_queries_from_pihole()
        
        if success:
            return jsonify({'status': 'success', 'message': 'All queries synced from Pi-hole database'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to sync queries'})
    except Exception as e:
        print(f"Error in force sync: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/search', methods=['GET'])
def search():
    """Search for devices and sites"""
    query = request.args.get('q', '').strip().lower()
    
    if not query or len(query) < 2:
        return jsonify({
            'devices': [],
            'sites': []
        })
    
    try:
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
        
        # Search sites - include device IP and hostname
        sites = conn.execute(
            '''SELECT 
                   dq.domain, 
                   SUM(dq.count) as total_count, 
                   MAX(dq.timestamp) as last_visited,
                   dq.device_ip,
                   d.hostname
               FROM dns_queries dq
               LEFT JOIN devices d ON dq.device_ip = d.ip
               WHERE LOWER(dq.domain) LIKE ?
               GROUP BY dq.domain, dq.device_ip
               ORDER BY total_count DESC
               LIMIT 50''',
            (f'%{query}%',)
        ).fetchall()
        
        # Group by domain and aggregate, keeping the device with most visits
        domain_map = {}
        for site in sites:
            domain = site['domain']
            if domain not in domain_map:
                domain_map[domain] = {
                    'domain': domain,
                    'total_count': 0,
                    'last_visited': site['last_visited'],
                    'device_ip': site['device_ip'],
                    'hostname': site['hostname']
                }
            domain_map[domain]['total_count'] += site['total_count']
            # Keep the device with the most recent visit or most visits
            if site['total_count'] > domain_map[domain].get('_max_device_count', 0):
                domain_map[domain]['device_ip'] = site['device_ip']
                domain_map[domain]['hostname'] = site['hostname']
                domain_map[domain]['_max_device_count'] = site['total_count']
            if site['last_visited'] > domain_map[domain]['last_visited']:
                domain_map[domain]['last_visited'] = site['last_visited']
        
        # Convert to list and remove internal tracking
        results['sites'] = []
        for domain_data in domain_map.values():
            del domain_data['_max_device_count']
            results['sites'].append(domain_data)
        
        # Sort by total count
        results['sites'].sort(key=lambda x: x['total_count'], reverse=True)
        results['sites'] = results['sites'][:20]  # Limit to top 20
        
        conn.close()
        return jsonify(results)
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e).lower():
            return jsonify({'error': 'Database temporarily locked, please try again'}), 503
        raise

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
    # Wait a moment for everything to initialize
    time.sleep(2)
    
    # Try Pi-hole first (if available, it's more reliable)
    print("Attempting to start Pi-hole reader...")
    if pihole.read_queries():
        # Pi-hole reading is active, don't use packet capture
        print("✓ Using Pi-hole query log. Packet capture not needed.")
        return
    
    # Fall back to packet capture if Pi-hole is not available
    print("Pi-hole not available, falling back to packet capture...")
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

