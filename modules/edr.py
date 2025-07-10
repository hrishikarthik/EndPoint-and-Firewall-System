"""
EDR Module - Endpoint Detection and Response
Process monitoring, file integrity, and behavior analysis
"""

import os
import psutil
import hashlib
import threading
import time
import logging
import json
import platform
import subprocess
from datetime import datetime
from typing import Dict, List, Set, Optional
from pathlib import Path

class EDRManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.processes = {}
        self.file_hashes = {}
        self.suspicious_processes = []
        self.suspicious_files = []
        self.behavior_alerts = []
        
        # Critical system directories to monitor
        self.critical_dirs = self._get_critical_directories()
        
        # Known good process hashes (simplified)
        self.known_good_hashes = set()
        
        # Suspicious process patterns
        self.suspicious_patterns = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe',
            'bitsadmin.exe', 'wmic.exe', 'schtasks.exe'
        ]
    
    def _get_critical_directories(self) -> List[str]:
        """Get platform-specific critical directories"""
        platform_sys = platform.system().lower()
        
        if platform_sys == "windows":
            return [
                os.path.expandvars("%SystemRoot%\\System32"),
                os.path.expandvars("%SystemRoot%\\SysWOW64"),
                os.path.expandvars("%ProgramFiles%"),
                os.path.expandvars("%ProgramFiles(x86)%")
            ]
        elif platform_sys == "linux":
            return [
                "/bin", "/sbin", "/usr/bin", "/usr/sbin",
                "/etc", "/var", "/boot"
            ]
        elif platform_sys == "darwin":  # macOS
            return [
                "/System/Library/CoreServices",
                "/usr/bin", "/usr/sbin", "/Applications"
            ]
        else:
            return []
    
    def start_monitoring(self):
        """Start EDR monitoring"""
        self.monitoring = True
        self.logger.info("Starting EDR monitoring")
        
        # Start process monitoring thread
        process_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        process_thread.start()
        
        # Start file monitoring thread
        file_thread = threading.Thread(target=self._monitor_files, daemon=True)
        file_thread.start()
        
        # Start behavior analysis thread
        behavior_thread = threading.Thread(target=self._analyze_behavior, daemon=True)
        behavior_thread.start()
    
    def stop_monitoring(self):
        """Stop EDR monitoring"""
        self.monitoring = False
        self.logger.info("Stopping EDR monitoring")
    
    def _monitor_processes(self):
        """Monitor running processes for suspicious activity"""
        while self.monitoring:
            try:
                current_processes = {}
                
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'cpu_percent', 'memory_percent']):
                    try:
                        proc_info = proc.info
                        pid = proc_info['pid']
                        
                        current_processes[pid] = {
                            'name': proc_info['name'],
                            'exe': proc_info['exe'],
                            'cmdline': proc_info['cmdline'],
                            'create_time': proc_info['create_time'],
                            'cpu_percent': proc_info['cpu_percent'],
                            'memory_percent': proc_info['memory_percent'],
                            'timestamp': datetime.now()
                        }
                        
                        # Check for suspicious processes
                        self._check_suspicious_process(proc)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                self.processes = current_processes
                time.sleep(2)  # Update every 2 seconds
                
            except Exception as e:
                self.logger.error(f"Error monitoring processes: {e}")
                time.sleep(5)
    
    def _monitor_files(self):
        """Monitor critical files for changes"""
        while self.monitoring:
            try:
                for directory in self.critical_dirs:
                    if os.path.exists(directory):
                        self._scan_directory(directory)
                
                time.sleep(30)  # Scan every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error monitoring files: {e}")
                time.sleep(60)
    
    def _scan_directory(self, directory: str):
        """Scan directory for file changes"""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Skip files that are too large or not accessible
                        if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100MB limit
                            continue
                        
                        file_hash = self._calculate_file_hash(file_path)
                        
                        if file_path in self.file_hashes:
                            if self.file_hashes[file_path] != file_hash:
                                # File has changed
                                self._alert_file_change(file_path, file_hash)
                        else:
                            # New file detected
                            self._alert_new_file(file_path, file_hash)
                        
                        self.file_hashes[file_path] = file_hash
                        
                    except (OSError, PermissionError):
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
    
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
    
    def _check_suspicious_process(self, proc):
        """Check if process is suspicious"""
        try:
            proc_info = proc.info
            name = proc_info['name'].lower()
            cmdline = proc_info['cmdline']
            
            suspicious_indicators = []
            
            # Check for suspicious process names
            if any(pattern in name for pattern in self.suspicious_patterns):
                suspicious_indicators.append(f"Suspicious process name: {name}")
            
            # Check for unusual CPU usage
            if proc_info['cpu_percent'] > 80:
                suspicious_indicators.append(f"High CPU usage: {proc_info['cpu_percent']}%")
            
            # Check for unusual memory usage
            if proc_info['memory_percent'] > 50:
                suspicious_indicators.append(f"High memory usage: {proc_info['memory_percent']}%")
            
            # Check for suspicious command line arguments
            if cmdline:
                suspicious_cmdline_patterns = [
                    'powershell -enc', 'cmd /c', 'wmic', 'schtasks',
                    'bitsadmin', 'certutil', 'reg add', 'netsh'
                ]
                
                cmdline_str = ' '.join(cmdline).lower()
                for pattern in suspicious_cmdline_patterns:
                    if pattern in cmdline_str:
                        suspicious_indicators.append(f"Suspicious command line: {pattern}")
                        break
            
            if suspicious_indicators:
                alert = {
                    'timestamp': datetime.now(),
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'exe': proc_info['exe'],
                    'cmdline': proc_info['cmdline'],
                    'indicators': suspicious_indicators,
                    'severity': 'HIGH' if len(suspicious_indicators) > 2 else 'MEDIUM'
                }
                
                self.suspicious_processes.append(alert)
                self.logger.warning(f"Suspicious process detected: {alert}")
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def _alert_file_change(self, file_path: str, new_hash: str):
        """Alert when a critical file has changed"""
        alert = {
            'timestamp': datetime.now(),
            'type': 'FILE_CHANGE',
            'file_path': file_path,
            'new_hash': new_hash,
            'old_hash': self.file_hashes.get(file_path, 'Unknown'),
            'severity': 'HIGH'
        }
        
        self.suspicious_files.append(alert)
        self.logger.warning(f"Critical file changed: {file_path}")
    
    def _alert_new_file(self, file_path: str, file_hash: str):
        """Alert when a new file is detected in critical directory"""
        alert = {
            'timestamp': datetime.now(),
            'type': 'NEW_FILE',
            'file_path': file_path,
            'hash': file_hash,
            'severity': 'MEDIUM'
        }
        
        self.suspicious_files.append(alert)
        self.logger.info(f"New file detected in critical directory: {file_path}")
    
    def _analyze_behavior(self):
        """Analyze process behavior patterns"""
        while self.monitoring:
            try:
                # Analyze process relationships
                self._analyze_process_relationships()
                
                # Analyze resource usage patterns
                self._analyze_resource_usage()
                
                # Analyze network connections by process
                self._analyze_process_network_activity()
                
                time.sleep(10)  # Analyze every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Error analyzing behavior: {e}")
                time.sleep(30)
    
    def _analyze_process_relationships(self):
        """Analyze parent-child process relationships"""
        try:
            for proc in psutil.process_iter(['pid', 'ppid', 'name']):
                try:
                    proc_info = proc.info
                    
                    # Check for unusual parent-child relationships
                    if proc_info['ppid']:
                        try:
                            parent = psutil.Process(proc_info['ppid'])
                            parent_name = parent.name().lower()
                            child_name = proc_info['name'].lower()
                            
                            # Check for suspicious parent-child combinations
                            suspicious_combinations = [
                                ('explorer.exe', 'cmd.exe'),
                                ('explorer.exe', 'powershell.exe'),
                                ('svchost.exe', 'cmd.exe'),
                                ('winlogon.exe', 'cmd.exe')
                            ]
                            
                            for parent_pattern, child_pattern in suspicious_combinations:
                                if parent_pattern in parent_name and child_pattern in child_name:
                                    alert = {
                                        'timestamp': datetime.now(),
                                        'type': 'SUSPICIOUS_PROCESS_RELATIONSHIP',
                                        'parent_pid': proc_info['ppid'],
                                        'parent_name': parent_name,
                                        'child_pid': proc_info['pid'],
                                        'child_name': child_name,
                                        'severity': 'HIGH'
                                    }
                                    
                                    self.behavior_alerts.append(alert)
                                    self.logger.warning(f"Suspicious process relationship: {alert}")
                                    break
                                    
                        except psutil.NoSuchProcess:
                            continue
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error analyzing process relationships: {e}")
    
    def _analyze_resource_usage(self):
        """Analyze unusual resource usage patterns"""
        try:
            high_cpu_processes = []
            high_memory_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    
                    if proc_info['cpu_percent'] > 70:
                        high_cpu_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cpu_percent': proc_info['cpu_percent']
                        })
                    
                    if proc_info['memory_percent'] > 30:
                        high_memory_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'memory_percent': proc_info['memory_percent']
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Alert if multiple processes are using high resources
            if len(high_cpu_processes) > 3:
                alert = {
                    'timestamp': datetime.now(),
                    'type': 'HIGH_CPU_USAGE',
                    'processes': high_cpu_processes,
                    'severity': 'MEDIUM'
                }
                self.behavior_alerts.append(alert)
            
            if len(high_memory_processes) > 3:
                alert = {
                    'timestamp': datetime.now(),
                    'type': 'HIGH_MEMORY_USAGE',
                    'processes': high_memory_processes,
                    'severity': 'MEDIUM'
                }
                self.behavior_alerts.append(alert)
                
        except Exception as e:
            self.logger.error(f"Error analyzing resource usage: {e}")
    
    def _analyze_process_network_activity(self):
        """Analyze network activity by process"""
        try:
            connections = psutil.net_connections()
            process_connections = {}
            
            for conn in connections:
                if conn.pid and conn.status == 'ESTABLISHED':
                    if conn.pid not in process_connections:
                        process_connections[conn.pid] = []
                    process_connections[conn.pid].append(conn)
            
            # Check for processes with unusual network activity
            for pid, conns in process_connections.items():
                if len(conns) > 10:  # More than 10 connections
                    try:
                        proc = psutil.Process(pid)
                        alert = {
                            'timestamp': datetime.now(),
                            'type': 'HIGH_NETWORK_ACTIVITY',
                            'pid': pid,
                            'name': proc.name(),
                            'connection_count': len(conns),
                            'severity': 'MEDIUM'
                        }
                        self.behavior_alerts.append(alert)
                    except psutil.NoSuchProcess:
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error analyzing process network activity: {e}")
    
    def kill_suspicious_process(self, pid: int):
        """Kill a suspicious process"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            self.logger.info(f"Terminated suspicious process: {pid}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to kill process {pid}: {e}")
            return False
    
    def quarantine_file(self, file_path: str):
        """Quarantine a suspicious file"""
        try:
            quarantine_dir = os.path.join(os.path.expanduser("~"), ".security_quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)
            
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_dir, f"quarantined_{filename}")
            
            # Move file to quarantine
            os.rename(file_path, quarantine_path)
            
            self.logger.info(f"Quarantined file: {file_path} -> {quarantine_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False
    
    def get_edr_stats(self) -> Dict:
        """Get EDR statistics"""
        return {
            'total_processes': len(self.processes),
            'suspicious_processes': len(self.suspicious_processes),
            'suspicious_files': len(self.suspicious_files),
            'behavior_alerts': len(self.behavior_alerts),
            'monitored_files': len(self.file_hashes),
            'monitoring': self.monitoring
        }
    
    def get_recent_alerts(self, alert_type: Optional[str] = None, limit: int = 10) -> List[Dict]:
        """Get recent alerts by type"""
        all_alerts = []
        
        if alert_type is None or alert_type == 'process':
            all_alerts.extend(self.suspicious_processes)
        if alert_type is None or alert_type == 'file':
            all_alerts.extend(self.suspicious_files)
        if alert_type is None or alert_type == 'behavior':
            all_alerts.extend(self.behavior_alerts)
        
        return sorted(all_alerts, key=lambda x: x['timestamp'], reverse=True)[:limit] 