#!/usr/bin/env python3
"""
Network Scanner - Discovers devices on the network
"""

import nmap
import sqlite3
from datetime import datetime
import netifaces
import socket
import warnings
import sys

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.db_file = 'network_monitoring.db'
        # Suppress netifaces warnings
        import logging
        logging.getLogger('netifaces').setLevel(logging.ERROR)
    
    def get_network_interface(self):
        """Get the default network interface"""
        try:
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            return default_interface
        except:
            return None
    
    def get_network_range(self):
        """Get the network range to scan"""
        try:
            # Suppress netifaces warnings about interfaces without IPv4
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning)
                interface = self.get_network_interface()
            
            if not interface:
                return None
            
            # Suppress warnings when checking addresses
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning)
                addrs = netifaces.ifaddresses(interface)
            
            if netifaces.AF_INET not in addrs:
                return None
            
            ip_info = addrs[netifaces.AF_INET][0]
            ip = ip_info['addr']
            netmask = ip_info.get('netmask', '255.255.255.0')
            
            # Calculate network range (simplified)
            ip_parts = ip.split('.')
            if netmask == '255.255.255.0':
                network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            else:
                # Default to /24 if we can't determine
                network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            return network
        except Exception as e:
            print(f"Error getting network range: {e}")
            return None
    
    def get_hostname(self, ip):
        """Get hostname for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def scan_network(self):
        """Scan the network for devices"""
        network_range = self.get_network_range()
        if not network_range:
            print("Could not determine network range")
            return
        
        print(f"Scanning network: {network_range}")
        
        try:
            # Try multiple scan methods for better device discovery
            # Method 1: ARP scan (fast, requires root on some systems)
            try:
                self.nm.scan(hosts=network_range, arguments='-sn --privileged')
                print(f"ARP scan found {len(self.nm.all_hosts())} hosts")
            except Exception as e:
                print(f"ARP scan failed (may need root): {e}")
                # Try without privileged mode
                try:
                    self.nm.scan(hosts=network_range, arguments='-sn')
                    print(f"Non-privileged scan found {len(self.nm.all_hosts())} hosts")
                except Exception as e2:
                    print(f"Non-privileged scan also failed: {e2}")
                    # Try ping scan as fallback
                    try:
                        self.nm.scan(hosts=network_range, arguments='-sn -PE')
                        print(f"Ping scan found {len(self.nm.all_hosts())} hosts")
                    except Exception as e3:
                        print(f"All scan methods failed: {e3}")
                        self.scan_local_network()
                        return
            
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            current_time = datetime.now().isoformat()
            devices_found = 0
            devices_updated = 0
            devices_new = 0
            
            for host in self.nm.all_hosts():
                try:
                    ip = host
                    mac = self.nm[host].get('addresses', {}).get('mac', 'unknown')
                    
                    # Skip if MAC is unknown (might be a false positive)
                    if mac == 'unknown':
                        # Try to get MAC from ARP table
                        mac = self.get_mac_from_arp(ip) or 'unknown'
                    
                    vendor = self.nm[host].get('vendor', {}).get(mac, 'Unknown')
                    hostname = self.get_hostname(ip) or 'Unknown'
                    
                    # Check if device exists
                    c.execute('SELECT * FROM devices WHERE mac = ?', (mac,))
                    existing = c.fetchone()
                    
                    if existing:
                        # Update last seen
                        c.execute(
                            'UPDATE devices SET last_seen = ?, ip = ? WHERE mac = ?',
                            (current_time, ip, mac)
                        )
                        devices_updated += 1
                    else:
                        # Insert new device
                        c.execute(
                            '''INSERT INTO devices (mac, ip, hostname, first_seen, last_seen, vendor)
                               VALUES (?, ?, ?, ?, ?, ?)''',
                            (mac, ip, hostname, current_time, current_time, vendor)
                        )
                        devices_new += 1
                    
                    devices_found += 1
                    conn.commit()
                except Exception as e:
                    print(f"Error processing host {host}: {e}")
                    continue
            
            conn.close()
            print(f"Scan complete. Found {devices_found} hosts ({devices_new} new, {devices_updated} updated)")
            
            # Also scan local network to ensure we have our own device
            self.scan_local_network()
            
        except Exception as e:
            print(f"Scan error: {e}")
            import traceback
            traceback.print_exc()
            # Fallback: try to get local network info
            self.scan_local_network()
    
    def get_mac_from_arp(self, ip):
        """Try to get MAC address from ARP table"""
        try:
            import subprocess
            import re
            # Try to read from /proc/net/arp (Linux)
            try:
                with open('/proc/net/arp', 'r') as f:
                    for line in f:
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                return parts[3]
            except:
                pass
            
            # Try arp command
            try:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', result.stdout)
                    if match:
                        return match.group(0)
            except:
                pass
        except:
            pass
        return None

    def scan_local_network(self):
        """Fallback: scan local network without nmap"""
        try:
            interface = self.get_network_interface()
            if not interface:
                return
            
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET not in addrs:
                return
            
            ip_info = addrs[netifaces.AF_INET][0]
            ip = ip_info['addr']
            mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'unknown')
            
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            current_time = datetime.now().isoformat()
            
            # Add local machine
            hostname = socket.gethostname()
            c.execute(
                '''INSERT OR REPLACE INTO devices (mac, ip, hostname, first_seen, last_seen, vendor)
                   VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM devices WHERE mac = ?), ?), ?, ?)''',
                (mac, ip, hostname, mac, current_time, current_time, 'Local Machine')
            )
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Local scan error: {e}")

