"""
Malicious Activity Detection Module
Heuristic-based detection and behavioral analysis
"""

import os
import psutil
import hashlib
import threading
import time
import logging
import json
import re
import platform
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from collections import defaultdict

class MaliciousDetection:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.detections = []
        self.suspicious_activities = []
        self.behavior_patterns = defaultdict(list)
        
        # Detection patterns
        self.malware_patterns = {
            'file_patterns': [
                r'\.exe$', r'\.dll$', r'\.bat$', r'\.cmd$', r'\.ps1$',
                r'\.vbs$', r'\.js$', r'\.jar$', r'\.scr$'
            ],
            'process_patterns': [
                r'cmd\.exe', r'powershell\.exe', r'wscript\.exe', r'cscript\.exe',
                r'rundll32\.exe', r'regsvr32\.exe', r'mshta\.exe', r'certutil\.exe'
            ],
            'network_patterns': [
                r'\.onion$', r'\.bit$', r'\.tor2web\.org$',
                r'\.malware\.', r'\.botnet\.', r'\.c2\.'
            ],
            'registry_patterns': [
                r'\\Run\\', r'\\RunOnce\\', r'\\Policies\\',
                r'\\CurrentVersion\\Run\\', r'\\CurrentVersion\\RunOnce\\'
            ]
        }
        
        # Behavioral indicators
        self.behavioral_indicators = {
            'file_operations': [
                'mass_file_creation', 'mass_file_deletion', 'file_encryption',
                'registry_modification', 'startup_modification'
            ],
            'network_operations': [
                'unusual_connections', 'data_exfiltration', 'command_control',
                'port_scanning', 'brute_force'
            ],
            'process_operations': [
                'process_injection', 'code_injection', 'privilege_escalation',
                'persistence_mechanism', 'anti_analysis'
            ]
        }
        
        # Known malicious hashes (simplified)
        self.known_malicious_hashes = set()
        
        # Activity thresholds
        self.thresholds = {
            'file_operations_per_minute': 50,
            'network_connections_per_minute': 100,
            'process_creations_per_minute': 20,
            'registry_modifications_per_minute': 10
        }
    
    def start_monitoring(self):
        """Start malicious activity monitoring"""
        self.monitoring = True
        self.logger.info("Starting malicious activity detection")
        
        # Start monitoring threads
        file_monitor_thread = threading.Thread(target=self._monitor_file_activity, daemon=True)
        file_monitor_thread.start()
        
        process_monitor_thread = threading.Thread(target=self._monitor_process_activity, daemon=True)
        process_monitor_thread.start()
        
        network_monitor_thread = threading.Thread(target=self._monitor_network_activity, daemon=True)
        network_monitor_thread.start()
        
        registry_monitor_thread = threading.Thread(target=self._monitor_registry_activity, daemon=True)
        registry_monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop malicious activity monitoring"""
        self.monitoring = False
        self.logger.info("Stopping malicious activity detection")
    
    def _monitor_file_activity(self):
        """Monitor file system activity for suspicious patterns"""
        while self.monitoring:
            try:
                # Monitor file operations using platform-specific methods
                if platform.system().lower() == "windows":
                    self._monitor_windows_file_activity()
                else:
                    self._monitor_unix_file_activity()
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error monitoring file activity: {e}")
                time.sleep(10)
    
    def _monitor_windows_file_activity(self):
        """Monitor Windows file activity"""
        try:
            # Check for suspicious file operations in common directories
            suspicious_dirs = [
                os.path.expandvars("%TEMP%"),
                os.path.expandvars("%TMP%"),
                os.path.expandvars("%APPDATA%"),
                os.path.expandvars("%LOCALAPPDATA%")
            ]
            
            for directory in suspicious_dirs:
                if os.path.exists(directory):
                    self._scan_directory_for_suspicious_files(directory)
                    
        except Exception as e:
            self.logger.error(f"Error in Windows file monitoring: {e}")
    
    def _monitor_unix_file_activity(self):
        """Monitor Unix file activity"""
        try:
            # Check for suspicious file operations
            suspicious_dirs = [
                '/tmp', '/var/tmp', '/dev/shm',
                os.path.expanduser('~/.cache'),
                os.path.expanduser('~/Downloads')
            ]
            
            for directory in suspicious_dirs:
                if os.path.exists(directory):
                    self._scan_directory_for_suspicious_files(directory)
                    
        except Exception as e:
            self.logger.error(f"Error in Unix file monitoring: {e}")
    
    def _scan_directory_for_suspicious_files(self, directory: str):
        """Scan directory for suspicious files"""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Check file extension patterns
                    if self._is_suspicious_filename(file):
                        self._alert_suspicious_file(file_path, "Suspicious filename pattern")
                    
                    # Check file content patterns
                    if self._is_suspicious_file_content(file_path):
                        self._alert_suspicious_file(file_path, "Suspicious file content")
                    
                    # Check file hash
                    file_hash = self._calculate_file_hash(file_path)
                    if file_hash in self.known_malicious_hashes:
                        self._alert_suspicious_file(file_path, "Known malicious hash")
                        
        except (OSError, PermissionError):
            pass
    
    def _is_suspicious_filename(self, filename: str) -> bool:
        """Check if filename matches suspicious patterns"""
        filename_lower = filename.lower()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            'malware', 'virus', 'trojan', 'backdoor', 'keylogger',
            'spyware', 'ransomware', 'botnet', 'crypto', 'miner',
            'stealer', 'injector', 'dropper', 'loader'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in filename_lower:
                return True
        
        # Check for suspicious extensions
        for pattern in self.malware_patterns['file_patterns']:
            if re.search(pattern, filename_lower):
                return True
        
        return False
    
    def _is_suspicious_file_content(self, file_path: str) -> bool:
        """Check if file content is suspicious"""
        try:
            # Only check small files to avoid performance issues
            if os.path.getsize(file_path) > 1024 * 1024:  # 1MB limit
                return False
            
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Read first 1KB
                
                # Check for suspicious strings
                suspicious_strings = [
                    b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
                    b'SetWindowsHookEx', b'RegCreateKey', b'RegSetValue',
                    b'URLDownloadToFile', b'WinExec', b'ShellExecute',
                    b'cmd.exe', b'powershell.exe', b'rundll32.exe'
                ]
                
                for suspicious_string in suspicious_strings:
                    if suspicious_string in content:
                        return True
                        
        except Exception:
            pass
        
        return False
    
    def _monitor_process_activity(self):
        """Monitor process creation and behavior"""
        while self.monitoring:
            try:
                current_processes = {}
                
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
                    try:
                        proc_info = proc.info
                        pid = proc_info['pid']
                        
                        current_processes[pid] = {
                            'name': proc_info['name'],
                            'exe': proc_info['exe'],
                            'cmdline': proc_info['cmdline'],
                            'create_time': proc_info['create_time']
                        }
                        
                        # Check for suspicious processes
                        self._check_suspicious_process(proc)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Track process creation patterns
                self._analyze_process_patterns(current_processes)
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                self.logger.error(f"Error monitoring process activity: {e}")
                time.sleep(5)
    
    def _check_suspicious_process(self, proc):
        """Check if process is suspicious"""
        try:
            proc_info = proc.info
            name = proc_info['name'].lower()
            cmdline = proc_info['cmdline']
            
            suspicious_indicators = []
            
            # Check process name patterns
            for pattern in self.malware_patterns['process_patterns']:
                if re.search(pattern, name):
                    suspicious_indicators.append(f"Suspicious process name: {name}")
                    break
            
            # Check command line arguments
            if cmdline:
                cmdline_str = ' '.join(cmdline).lower()
                suspicious_cmdline_patterns = [
                    'powershell -enc', 'cmd /c', 'wmic', 'schtasks',
                    'bitsadmin', 'certutil', 'reg add', 'netsh',
                    'rundll32', 'regsvr32', 'mshta'
                ]
                
                for pattern in suspicious_cmdline_patterns:
                    if pattern in cmdline_str:
                        suspicious_indicators.append(f"Suspicious command line: {pattern}")
                        break
            
            # Check for process injection indicators
            if self._check_process_injection(proc):
                suspicious_indicators.append("Potential process injection detected")
            
            if suspicious_indicators:
                alert = {
                    'timestamp': datetime.now(),
                    'type': 'SUSPICIOUS_PROCESS',
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'exe': proc_info['exe'],
                    'cmdline': proc_info['cmdline'],
                    'indicators': suspicious_indicators,
                    'severity': 'HIGH' if len(suspicious_indicators) > 2 else 'MEDIUM'
                }
                
                self.suspicious_activities.append(alert)
                self.logger.warning(f"Suspicious process detected: {alert}")
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def _check_process_injection(self, proc) -> bool:
        """Check for signs of process injection"""
        try:
            # Check for unusual memory regions
            memory_maps = proc.memory_maps()
            
            # Look for suspicious memory patterns
            suspicious_memory_patterns = [
                'rwxp', 'rwx', 'r-xp'  # Executable memory regions
            ]
            
            for memory_map in memory_maps:
                if any(pattern in memory_map.path.lower() for pattern in suspicious_memory_patterns):
                    return True
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return False
    
    def _monitor_network_activity(self):
        """Monitor network activity for suspicious patterns"""
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        # Check for suspicious network patterns
                        self._check_suspicious_network_activity(conn)
                
                time.sleep(3)  # Check every 3 seconds
                
            except Exception as e:
                self.logger.error(f"Error monitoring network activity: {e}")
                time.sleep(5)
    
    def _check_suspicious_network_activity(self, conn):
        """Check if network activity is suspicious"""
        try:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            
            suspicious_indicators = []
            
            # Check for suspicious ports
            suspicious_ports = [4444, 8080, 1337, 31337, 6667, 6668, 6669]
            if remote_port in suspicious_ports:
                suspicious_indicators.append(f"Suspicious port: {remote_port}")
            
            # Check for suspicious IP patterns
            if self._is_suspicious_ip(remote_ip):
                suspicious_indicators.append(f"Suspicious IP: {remote_ip}")
            
            # Check for data exfiltration patterns
            if self._check_data_exfiltration(conn):
                suspicious_indicators.append("Potential data exfiltration")
            
            if suspicious_indicators:
                alert = {
                    'timestamp': datetime.now(),
                    'type': 'SUSPICIOUS_NETWORK',
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_addr': f"{remote_ip}:{remote_port}",
                    'indicators': suspicious_indicators,
                    'severity': 'HIGH' if len(suspicious_indicators) > 2 else 'MEDIUM'
                }
                
                self.suspicious_activities.append(alert)
                self.logger.warning(f"Suspicious network activity: {alert}")
                
        except Exception as e:
            self.logger.error(f"Error checking network activity: {e}")
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious"""
        # Check for known malicious IP patterns
        suspicious_ip_patterns = [
            '0.0.0.0', '255.255.255.255',
            '127.0.0.1', 'localhost'
        ]
        
        return any(pattern in ip for pattern in suspicious_ip_patterns)
    
    def _check_data_exfiltration(self, conn) -> bool:
        """Check for signs of data exfiltration"""
        try:
            # This is a simplified check - in a real implementation,
            # you would analyze packet contents and data flow patterns
            return False
        except Exception:
            return False
    
    def _monitor_registry_activity(self):
        """Monitor registry activity (Windows only)"""
        if platform.system().lower() != "windows":
            return
        
        while self.monitoring:
            try:
                # Monitor registry changes using Windows API
                # This is a simplified implementation
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Error monitoring registry activity: {e}")
                time.sleep(30)
    
    def _analyze_process_patterns(self, current_processes: Dict):
        """Analyze process creation patterns"""
        try:
            # Track process creation frequency
            current_time = time.time()
            
            # Remove old entries (older than 1 minute)
            self.behavior_patterns['process_creations'] = [
                entry for entry in self.behavior_patterns['process_creations']
                if current_time - entry['timestamp'] < 60
            ]
            
            # Check for rapid process creation
            if len(self.behavior_patterns['process_creations']) > self.thresholds['process_creations_per_minute']:
                alert = {
                    'timestamp': datetime.now(),
                    'type': 'RAPID_PROCESS_CREATION',
                    'description': f"High rate of process creation: {len(self.behavior_patterns['process_creations'])} in last minute",
                    'severity': 'MEDIUM'
                }
                self.suspicious_activities.append(alert)
                
        except Exception as e:
            self.logger.error(f"Error analyzing process patterns: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def _alert_suspicious_file(self, file_path: str, reason: str):
        """Alert about suspicious file"""
        alert = {
            'timestamp': datetime.now(),
            'type': 'SUSPICIOUS_FILE',
            'file_path': file_path,
            'reason': reason,
            'severity': 'HIGH'
        }
        
        self.suspicious_activities.append(alert)
        self.logger.warning(f"Suspicious file detected: {alert}")
    
    def add_malicious_hash(self, file_hash: str):
        """Add a known malicious hash to the database"""
        self.known_malicious_hashes.add(file_hash)
        self.logger.info(f"Added malicious hash: {file_hash}")
    
    def get_detection_stats(self) -> Dict:
        """Get detection statistics"""
        return {
            'total_detections': len(self.detections),
            'suspicious_activities': len(self.suspicious_activities),
            'known_malicious_hashes': len(self.known_malicious_hashes),
            'monitoring': self.monitoring
        }
    
    def get_recent_detections(self, limit: int = 10) -> List[Dict]:
        """Get recent detections"""
        return sorted(self.suspicious_activities, 
                     key=lambda x: x['timestamp'], 
                     reverse=True)[:limit] 