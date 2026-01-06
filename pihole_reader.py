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

