#!/usr/bin/env python3
"""
Packet Capture - Captures DNS queries to track visited sites
"""

from scapy.all import sniff, IP, UDP, DNS, DNSQR, get_if_list, conf
import sqlite3
from datetime import datetime
from collections import defaultdict
import threading
import time
import netifaces
import subprocess
import platform

class PacketCapture:
    def __init__(self):
        self.db_file = 'network_monitoring.db'
        self.capturing = False
        self.dns_cache = defaultdict(lambda: defaultdict(int))  # {device_ip: {domain: count}}
        self.cache_lock = threading.Lock()
        self.last_flush = time.time()
        self.flush_interval = 30  # Flush to DB every 30 seconds
        self.interface = None
        self.capture_stats = {'total_packets': 0, 'unique_ips': set(), 'last_print': time.time()}
    
    def get_network_interface(self):
        """Get the default network interface"""
        try:
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            return default_interface
        except:
            return None
    
    def enable_promiscuous_mode(self, interface):
        """Enable promiscuous mode on the network interface"""
        if not interface:
            return False
        
        try:
            system = platform.system()
            if system == 'Darwin':  # macOS
                # On macOS, promiscuous mode is usually enabled automatically by libpcap
                # But we can try to set it explicitly
                subprocess.run(['sudo', 'ifconfig', interface, 'promisc'], 
                            check=False, capture_output=True)
                return True
            elif system == 'Linux':
                subprocess.run(['sudo', 'ifconfig', interface, 'promisc'], 
                            check=False, capture_output=True)
                return True
            elif system == 'Windows':
                # Windows doesn't use ifconfig, promiscuous mode is handled by WinPcap/Npcap
                return True
            return True
        except Exception as e:
            print(f"Warning: Could not enable promiscuous mode: {e}")
            print("Note: Promiscuous mode may still work depending on your system")
            return False
    
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
    
    def process_dns_packet(self, packet):
        """Process DNS query packet"""
        try:
            if packet.haslayer(DNS) and packet.haslayer(IP):
                dns_layer = packet[DNS]
                
                # Process both queries and responses
                # Queries: track who is asking
                # Responses: track who received the response (destination)
                if dns_layer.qd:  # Has a question
                    query = dns_layer.qd
                    domain = query.qname.decode('utf-8').rstrip('.')
                    
                    # Skip local domains and invalid domains
                    if domain and '.' in domain and not domain.startswith('.'):
                        if dns_layer.qr == 0:
                            # DNS Query - source IP is making the query
                            src_ip = packet[IP].src
                        else:
                            # DNS Response - destination IP received the response
                            src_ip = packet[IP].dst
                        
                        # Cache the DNS query
                        with self.cache_lock:
                            self.dns_cache[src_ip][domain] += 1
                            self.capture_stats['total_packets'] += 1
                            self.capture_stats['unique_ips'].add(src_ip)
                        
                        # Print stats every 60 seconds
                        current_time = time.time()
                        if current_time - self.capture_stats['last_print'] > 60:
                            with self.cache_lock:
                                unique_count = len(self.capture_stats['unique_ips'])
                                print(f"Capture stats: {self.capture_stats['total_packets']} DNS packets from {unique_count} unique IPs")
                                self.capture_stats['last_print'] = current_time
                        
                        # Flush to DB periodically
                        if current_time - self.last_flush > self.flush_interval:
                            self.flush_to_db()
                            self.last_flush = current_time
        except Exception as e:
            pass  # Silently ignore packet processing errors
    
    def flush_to_db(self):
        """Flush cached DNS queries to database"""
        with self.cache_lock:
            if not self.dns_cache:
                return
            
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            current_time = datetime.now().isoformat()
            
            for device_ip, domains in self.dns_cache.items():
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
            self.dns_cache.clear()
    
    def capture_packets(self):
        """Start capturing DNS packets"""
        if self.capturing:
            return
        
        self.capturing = True
        
        try:
            # Get network interface
            self.interface = self.get_network_interface()
            
            if not self.interface:
                print("Warning: Could not determine network interface. Trying default...")
                # Try to use the first available interface
                try:
                    interfaces = get_if_list()
                    if interfaces:
                        self.interface = interfaces[0]
                        print(f"Using interface: {self.interface}")
                except:
                    pass
            
            # Enable promiscuous mode
            if self.interface:
                print(f"Enabling promiscuous mode on {self.interface}...")
                self.enable_promiscuous_mode(self.interface)
                print(f"Capturing DNS packets on interface: {self.interface}")
            else:
                print("Capturing DNS packets on all interfaces...")
            
            # Note: This requires root/admin privileges
            print("Starting packet capture (requires root/admin privileges)...")
            print("Note: On switched networks, you may only see traffic destined for this device.")
            print("      To capture all network traffic, you may need port mirroring or a network tap.")
            print("      If running on Pi-hole, the tool will automatically use Pi-hole's query log instead.")
            
            # Use timeout to allow periodic flushing
            while self.capturing:
                try:
                    # Capture with interface specified and promiscuous mode
                    sniff_kwargs = {
                        'filter': 'udp port 53',
                        'prn': self.process_dns_packet,
                        'store': False,
                        'timeout': 5,
                        'stop_filter': lambda x: not self.capturing
                    }
                    
                    # Add interface if available
                    if self.interface:
                        sniff_kwargs['iface'] = self.interface
                    
                    # Enable promiscuous mode in scapy
                    conf.sniff_promisc = True
                    
                    sniff(**sniff_kwargs)
                    
                    # Flush periodically
                    self.flush_to_db()
                except Exception as e:
                    if self.capturing:
                        print(f"Capture iteration error: {e}")
                        time.sleep(5)
        except PermissionError:
            print("Permission denied: Packet capture requires root/admin privileges")
            print("Please run with sudo (Linux/Mac) or as Administrator (Windows)")
            self.capturing = False
        except Exception as e:
            print(f"Packet capture error: {e}")
            print("Trying to continue with default settings...")
            # Try without interface specification
            try:
                conf.sniff_promisc = True
                while self.capturing:
                    sniff(
                        filter="udp port 53",
                        prn=self.process_dns_packet,
                        store=False,
                        timeout=5,
                        stop_filter=lambda x: not self.capturing
                    )
                    self.flush_to_db()
            except Exception as e2:
                print(f"Fallback capture also failed: {e2}")
                self.capturing = False
    
    def stop_capture(self):
        """Stop packet capture"""
        self.capturing = False
        self.flush_to_db()

