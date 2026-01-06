#!/usr/bin/env python3
"""
Pi-hole Query Log Reader - Reads DNS queries from Pi-hole's database/log
"""

import sqlite3
import os
import threading
import time
from datetime import datetime
from collections import defaultdict

class PiholeReader:
    def __init__(self):
        self.db_file = 'network_monitoring.db'
        self.pihole_db_paths = [
            '/etc/pihole/pihole-FTL.db',  # Standard Pi-hole location
            '/var/log/pihole.log',  # Log file fallback
        ]
        self.pihole_db = None
        self.reading = False
        self.query_cache = defaultdict(lambda: defaultdict(int))  # {device_ip: {domain: count}}
        self.cache_lock = threading.Lock()
        self.last_flush = time.time()
        self.flush_interval = 30  # Flush to DB every 30 seconds
        self.last_timestamp = None  # Track last processed query timestamp
    
    def detect_pihole(self):
        """Detect if Pi-hole is installed and find the database"""
        for path in self.pihole_db_paths:
            if os.path.exists(path):
                if path.endswith('.db'):
                    try:
                        # Try to open the database
                        test_conn = sqlite3.connect(path)
                        test_conn.close()
                        return path
                    except:
                        continue
                elif path.endswith('.log'):
                    # Check if it's readable
                    if os.access(path, os.R_OK):
                        return path
        return None
    
    def get_device_mac(self, ip):
        """Get MAC address for an IP from devices table"""
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            result = c.execute(
                'SELECT mac FROM devices WHERE ip = ? LIMIT 1',
                (ip,)
            ).fetchone()
            conn.close()
            
            if result:
                return result[0]
            return None
        except:
            return None
    
    def get_devices_from_pihole(self):
        """Get unique devices (clients) from Pi-hole's database"""
        try:
            if not self.pihole_db or not self.pihole_db.endswith('.db'):
                print("Pi-hole database not available for device discovery")
                return []
            
            conn = sqlite3.connect(self.pihole_db, timeout=5.0)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            devices = {}
            
            # Method 1: Get unique clients from queries table (most reliable)
            try:
                query = '''
                    SELECT DISTINCT client as ip, MAX(timestamp) as last_seen
                    FROM queries 
                    WHERE client IS NOT NULL AND client != '' AND client != 'unknown'
                    GROUP BY client
                '''
                c.execute(query)
                rows = c.fetchall()
                
                for row in rows:
                    ip = row['ip']
                    if ip and ip != 'unknown' and ip != '':
                        # Convert timestamp if needed
                        last_seen = row['last_seen']
                        if isinstance(last_seen, (int, float)):
                            last_seen = datetime.fromtimestamp(last_seen).isoformat()
                        elif isinstance(last_seen, str):
                            try:
                                # Try to parse as timestamp
                                last_seen = datetime.fromtimestamp(float(last_seen)).isoformat()
                            except:
                                pass
                        
                        devices[ip] = {
                            'ip': ip,
                            'mac': 'unknown',
                            'hostname': 'Unknown',
                            'last_seen': last_seen
                        }
                
                print(f"Found {len(devices)} unique clients from queries table")
            except Exception as e:
                print(f"Error reading queries table: {e}")
                import traceback
                traceback.print_exc()
            
            # Method 2: Try network table (Pi-hole 5.0+) for more details
            try:
                c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='network'")
                if c.fetchone():
                    network_query = '''
                        SELECT hwaddr as mac, ip, name as hostname, lastQuery as last_seen
                        FROM network
                        WHERE ip IS NOT NULL AND ip != ''
                    '''
                    c.execute(network_query)
                    network_rows = c.fetchall()
                    
                    for row in network_rows:
                        ip = row['ip']
                        if ip:
                            # Convert timestamp
                            last_seen = row.get('last_seen', time.time())
                            if isinstance(last_seen, (int, float)):
                                last_seen = datetime.fromtimestamp(last_seen).isoformat()
                            elif isinstance(last_seen, str):
                                try:
                                    last_seen = datetime.fromtimestamp(float(last_seen)).isoformat()
                                except:
                                    pass
                            
                            # Update or add device with better info
                            if ip in devices:
                                devices[ip]['mac'] = row.get('mac', devices[ip].get('mac', 'unknown'))
                                devices[ip]['hostname'] = row.get('hostname', devices[ip].get('hostname', 'Unknown'))
                            else:
                                devices[ip] = {
                                    'ip': ip,
                                    'mac': row.get('mac', 'unknown'),
                                    'hostname': row.get('hostname', 'Unknown'),
                                    'last_seen': last_seen
                                }
                    
                    print(f"Updated {len(network_rows)} devices from network table")
            except Exception as e:
                print(f"Could not read network table (may not exist): {e}")
            
            conn.close()
            
            print(f"Total unique devices found in Pi-hole: {len(devices)}")
            return list(devices.values())
        except Exception as e:
            print(f"Error getting devices from Pi-hole: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def read_pihole_db(self):
        """Read queries from Pi-hole's SQLite database"""
        try:
            conn = sqlite3.connect(self.pihole_db, timeout=5.0)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Pi-hole FTL database structure
            # Query table has: id, timestamp, type, status, domain, client, forward, reply_type, reply_time
            # Try to get table structure first
            try:
                c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='queries'")
                if not c.fetchone():
                    # Table might not exist or have different name
                    conn.close()
                    return []
            except:
                conn.close()
                return []
            
            # Build query based on available columns
            query = '''
                SELECT timestamp, domain, client 
                FROM queries 
                WHERE timestamp > ?
                ORDER BY timestamp ASC
                LIMIT 1000
            '''
            
            # Use epoch timestamp or last processed timestamp
            if self.last_timestamp:
                c.execute(query, (self.last_timestamp,))
            else:
                # First run - get queries from last hour
                one_hour_ago = int(time.time()) - 3600
                c.execute(query, (one_hour_ago,))
            
            rows = c.fetchall()
            conn.close()
            
            # Convert to list of tuples
            result = []
            for row in rows:
                result.append((row['timestamp'], row['domain'], row['client']))
            
            return result
        except Exception as e:
            print(f"Error reading Pi-hole database: {e}")
            # Try to get column names for debugging
            try:
                conn = sqlite3.connect(self.pihole_db, timeout=5.0)
                c = conn.cursor()
                c.execute("PRAGMA table_info(queries)")
                columns = c.fetchall()
                print(f"Available columns: {[col[1] for col in columns]}")
                conn.close()
            except:
                pass
            return []
    
    def read_pihole_log(self):
        """Read queries from Pi-hole's log file (fallback)"""
        try:
            queries = []
            with open(self.pihole_db, 'r') as f:
                # Read from end of file (new queries)
                # Pi-hole log format: timestamp domain client
                # Example: 1234567890 example.com 192.168.1.100
                lines = f.readlines()
                for line in lines[-1000:]:  # Read last 1000 lines
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        try:
                            timestamp = int(parts[0])
                            domain = parts[1]
                            client = parts[2]
                            if timestamp > (self.last_timestamp or 0):
                                queries.append((timestamp, domain, client))
                        except:
                            continue
            return queries
        except Exception as e:
            print(f"Error reading Pi-hole log: {e}")
            return []
    
    def process_queries(self, queries):
        """Process queries from Pi-hole"""
        current_time = time.time()
        
        for query in queries:
            try:
                if len(query) >= 3:
                    timestamp = query[0]
                    domain = query[1]
                    client_ip = query[2]
                    
                    # Update last timestamp
                    if not self.last_timestamp or timestamp > self.last_timestamp:
                        self.last_timestamp = timestamp
                    
                    # Skip invalid domains
                    if not domain or '.' not in domain or domain.startswith('.'):
                        continue
                    
                    # Cache the query
                    with self.cache_lock:
                        self.query_cache[client_ip][domain] += 1
                    
                    # Flush periodically
                    if current_time - self.last_flush > self.flush_interval:
                        self.flush_to_db()
                        self.last_flush = current_time
            except Exception as e:
                continue
    
    def flush_to_db(self):
        """Flush cached queries to database"""
        with self.cache_lock:
            if not self.query_cache:
                return
            
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            current_time = datetime.now().isoformat()
            
            for device_ip, domains in self.query_cache.items():
                device_mac = self.get_device_mac(device_ip)
                if not device_mac:
                    # Try to create device entry if it doesn't exist
                    device_mac = 'unknown'
                    c.execute(
                        '''INSERT OR IGNORE INTO devices (mac, ip, hostname, first_seen, last_seen, vendor)
                           VALUES (?, ?, ?, ?, ?, ?)''',
                        (device_mac, device_ip, 'Unknown', current_time, current_time, 'Unknown')
                    )
                
                for domain, count in domains.items():
                    # Insert or update DNS query
                    c.execute(
                        '''INSERT INTO dns_queries (device_mac, device_ip, domain, timestamp, count)
                           VALUES (?, ?, ?, ?, ?)''',
                        (device_mac, device_ip, domain, current_time, count)
                    )
            
            conn.commit()
            conn.close()
            
            # Clear cache
            self.query_cache.clear()
    
    def sync_devices_from_pihole(self):
        """Sync devices from Pi-hole to monitoring database"""
        try:
            print("Starting device sync from Pi-hole...")
            devices = self.get_devices_from_pihole()
            
            if not devices:
                print("No devices found in Pi-hole database")
                return
            
            print(f"Syncing {len(devices)} devices to monitoring database...")
            
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            current_time = datetime.now().isoformat()
            
            synced_count = 0
            updated_count = 0
            new_count = 0
            
            for device in devices:
                try:
                    ip = device.get('ip')
                    if not ip or ip == 'unknown' or ip == '':
                        continue
                    
                    mac = device.get('mac', 'unknown')
                    hostname = device.get('hostname', 'Unknown')
                    last_seen = device.get('last_seen', current_time)
                    
                    # Ensure last_seen is a string
                    if isinstance(last_seen, (int, float)):
                        last_seen = datetime.fromtimestamp(last_seen).isoformat()
                    elif not isinstance(last_seen, str):
                        last_seen = current_time
                    
                    # Check if device exists by IP or MAC
                    c.execute('SELECT mac FROM devices WHERE ip = ? OR (mac = ? AND mac != "unknown")', (ip, mac))
                    existing = c.fetchone()
                    
                    if existing:
                        # Update existing device
                        existing_mac = existing[0]
                        c.execute(
                            'UPDATE devices SET last_seen = ?, ip = ?, hostname = ? WHERE ip = ? OR mac = ?',
                            (last_seen, ip, hostname, ip, existing_mac)
                        )
                        updated_count += 1
                    else:
                        # Insert new device
                        # Use IP-based MAC if MAC is unknown
                        device_mac = mac if mac != 'unknown' else f"pihole-{ip.replace('.', '-')}"
                        c.execute(
                            '''INSERT INTO devices (mac, ip, hostname, first_seen, last_seen, vendor)
                               VALUES (?, ?, ?, ?, ?, ?)''',
                            (device_mac, ip, hostname, last_seen, last_seen, 'Pi-hole Client')
                        )
                        new_count += 1
                    
                    synced_count += 1
                    conn.commit()
                except Exception as e:
                    print(f"Error syncing device {device}: {e}")
                    import traceback
                    traceback.print_exc()
                    continue
            
            conn.close()
            print(f"Device sync complete: {synced_count} total ({new_count} new, {updated_count} updated)")
        except Exception as e:
            print(f"Error syncing devices from Pi-hole: {e}")
            import traceback
            traceback.print_exc()
    
    def read_queries(self):
        """Main loop to read queries from Pi-hole"""
        if self.reading:
            return
        
        self.pihole_db = self.detect_pihole()
        
        if not self.pihole_db:
            print("Pi-hole not detected. Using packet capture instead.")
            return False
        
        print(f"Pi-hole detected! Reading queries from: {self.pihole_db}")
        self.reading = True
        
        # Sync devices from Pi-hole on startup (wait a moment for DB to be ready)
        if self.pihole_db.endswith('.db'):
            print("Waiting 2 seconds before initial device sync...")
            time.sleep(2)
            print("Syncing devices from Pi-hole on startup...")
            self.sync_devices_from_pihole()
        
        try:
            while self.reading:
                try:
                    if self.pihole_db.endswith('.db'):
                        queries = self.read_pihole_db()
                    else:
                        queries = self.read_pihole_log()
                    
                    if queries:
                        self.process_queries(queries)
                        print(f"Processed {len(queries)} queries from Pi-hole")
                    
                    # Sync devices periodically (every 5 minutes)
                    if int(time.time()) % 300 < 5 and self.pihole_db.endswith('.db'):
                        self.sync_devices_from_pihole()
                    
                    # Check every 5 seconds
                    time.sleep(5)
                except Exception as e:
                    print(f"Error reading Pi-hole queries: {e}")
                    time.sleep(10)
        except KeyboardInterrupt:
            self.reading = False
        finally:
            self.flush_to_db()
        
        return True
    
    def stop_reading(self):
        """Stop reading from Pi-hole"""
        self.reading = False
        self.flush_to_db()

