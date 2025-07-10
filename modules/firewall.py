"""
Firewall Module - Network monitoring and packet filtering
"""

import socket
import threading
import time
import logging
import psutil
import platform
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

class FirewallManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.connections = {}
        self.blocked_ips = set()
        self.allowed_ports = {80, 443, 22, 21, 25, 53}  # Common ports
        self.suspicious_connections = []
        
        # Platform-specific initialization
        self.platform = platform.system().lower()
        self.setup_platform_firewall()
    
    def setup_platform_firewall(self):
        """Setup platform-specific firewall rules"""
        try:
            if self.platform == "windows":
                self.setup_windows_firewall()
            elif self.platform == "linux":
                self.setup_linux_firewall()
            elif self.platform == "darwin":  # macOS
                self.setup_macos_firewall()
            else:
                self.logger.warning(f"Unsupported platform: {self.platform}")
        except Exception as e:
            self.logger.error(f"Failed to setup platform firewall: {e}")
    
    def setup_windows_firewall(self):
        """Setup Windows firewall rules"""
        try:
            # Enable Windows Firewall
            subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'], 
                         capture_output=True, check=True)
            self.logger.info("Windows Firewall enabled")
        except Exception as e:
            self.logger.error(f"Failed to setup Windows firewall: {e}")
    
    def setup_linux_firewall(self):
        """Setup Linux iptables rules"""
        try:
            # Basic iptables rules (requires root)
            rules = [
                ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
                ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'],
                ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'],
                ['iptables', '-A', 'INPUT', '-j', 'DROP']
            ]
            
            for rule in rules:
                try:
                    subprocess.run(rule, capture_output=True, check=True)
                except subprocess.CalledProcessError:
                    self.logger.warning(f"Failed to apply iptables rule: {rule}")
                    
            self.logger.info("Linux firewall rules applied")
        except Exception as e:
            self.logger.error(f"Failed to setup Linux firewall: {e}")
    
    def setup_macos_firewall(self):
        """Setup macOS firewall rules"""
        try:
            # Enable macOS firewall
            subprocess.run(['sudo', '/usr/libexec/ApplicationFirewall/socketfilterfw', '--setglobalstate', 'on'], 
                         capture_output=True)
            self.logger.info("macOS firewall enabled")
        except Exception as e:
            self.logger.error(f"Failed to setup macOS firewall: {e}")
    
    def start_monitoring(self):
        """Start network monitoring"""
        self.monitoring = True
        self.logger.info("Starting firewall monitoring")
        
        # Start connection monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_connections, daemon=True)
        monitor_thread.start()
        
        # Start packet analysis thread
        packet_thread = threading.Thread(target=self._analyze_packets, daemon=True)
        packet_thread.start()
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        self.logger.info("Stopping firewall monitoring")
    
    def _monitor_connections(self):
        """Monitor active network connections"""
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                current_connections = {}
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                        try:
                            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                            key = f"{local_addr}-{remote_addr}"
                            current_connections[key] = {
                                'local_addr': local_addr,
                                'remote_addr': remote_addr,
                                'status': conn.status,
                                'pid': conn.pid,
                                'timestamp': datetime.now()
                            }
                            
                            # Check for suspicious connections
                            self._check_suspicious_connection(conn)
                        except (AttributeError, TypeError) as e:
                            self.logger.debug(f"Error processing connection: {e}")
                            continue
                
                self.connections = current_connections
                time.sleep(1)  # Update every second
                
            except Exception as e:
                self.logger.error(f"Error monitoring connections: {e}")
                time.sleep(5)
    
    def _analyze_packets(self):
        """Analyze network packets for threats"""
        while self.monitoring:
            try:
                # Analyze network interfaces
                interfaces = psutil.net_if_addrs()
                
                for interface, addrs in interfaces.items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:  # IPv4
                            self._analyze_interface_traffic(interface, addr.address)
                
                time.sleep(5)  # Analyze every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error analyzing packets: {e}")
                time.sleep(10)
    
    def _analyze_interface_traffic(self, interface: str, ip: str):
        """Analyze traffic on specific interface"""
        try:
            # Get interface statistics
            stats = psutil.net_io_counters(pernic=True).get(interface)
            if stats:
                # Check for unusual traffic patterns
                if stats.bytes_sent > 1000000 or stats.bytes_recv > 1000000:  # 1MB threshold
                    self.logger.warning(f"High traffic detected on {interface}: {stats.bytes_sent} sent, {stats.bytes_recv} received")
                    
        except Exception as e:
            self.logger.error(f"Error analyzing interface {interface}: {e}")
    
    def _check_suspicious_connection(self, conn):
        """Check if connection is suspicious"""
        suspicious_indicators = []
        
        # Check for suspicious ports
        if conn.raddr.port in [4444, 8080, 1337, 31337]:  # Common malware ports
            suspicious_indicators.append(f"Suspicious port: {conn.raddr.port}")
        
        # Check for suspicious IP patterns
        remote_ip = conn.raddr.ip
        if self._is_suspicious_ip(remote_ip):
            suspicious_indicators.append(f"Suspicious IP: {remote_ip}")
        
        # Check for unusual connection patterns
        if conn.pid:
            try:
                process = psutil.Process(conn.pid)
                if self._is_suspicious_process(process):
                    suspicious_indicators.append(f"Suspicious process: {process.name()}")
            except psutil.NoSuchProcess:
                pass
        
        if suspicious_indicators:
            alert = {
                'timestamp': datetime.now(),
                'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                'indicators': suspicious_indicators,
                'severity': 'HIGH' if len(suspicious_indicators) > 2 else 'MEDIUM'
            }
            
            self.suspicious_connections.append(alert)
            self.logger.warning(f"Suspicious connection detected: {alert}")
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious"""
        # Check for private IP ranges
        if ip.startswith(('10.', '172.16.', '192.168.')):
            return False  # Private IPs are usually safe
        
        # Check for known malicious IP patterns (simplified)
        suspicious_patterns = [
            '0.0.0.0',
            '255.255.255.255'
        ]
        
        return any(pattern in ip for pattern in suspicious_patterns)
    
    def _is_suspicious_process(self, process) -> bool:
        """Check if process is suspicious"""
        suspicious_names = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe'
        ]
        
        return process.name().lower() in suspicious_names
    
    def block_ip(self, ip: str):
        """Block an IP address"""
        try:
            if self.platform == "windows":
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                             f'name="Block {ip}"', 'dir=in', 'action=block',
                             f'remoteip={ip}'], capture_output=True, check=True)
            elif self.platform == "linux":
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], 
                             capture_output=True, check=True)
            
            self.blocked_ips.add(ip)
            self.logger.info(f"Blocked IP: {ip}")
            
        except Exception as e:
            self.logger.error(f"Failed to block IP {ip}: {e}")
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        try:
            if self.platform == "windows":
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                             f'name="Block {ip}"'], capture_output=True)
            elif self.platform == "linux":
                subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], 
                             capture_output=True)
            
            self.blocked_ips.discard(ip)
            self.logger.info(f"Unblocked IP: {ip}")
            
        except Exception as e:
            self.logger.error(f"Failed to unblock IP {ip}: {e}")
    
    def get_connection_stats(self) -> Dict:
        """Get current connection statistics"""
        return {
            'total_connections': len(self.connections),
            'blocked_ips': len(self.blocked_ips),
            'suspicious_connections': len(self.suspicious_connections),
            'platform': self.platform,
            'monitoring': self.monitoring
        }
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """Get recent security alerts"""
        return sorted(self.suspicious_connections, 
                     key=lambda x: x['timestamp'], 
                     reverse=True)[:limit] 