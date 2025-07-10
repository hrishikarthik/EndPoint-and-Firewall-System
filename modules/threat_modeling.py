"""
Threat Modeling Module - Risk assessment and attack surface analysis
"""

import os
import platform
import subprocess
import socket
import psutil
import json
import logging
from datetime import datetime
from typing import Dict, List, Set, Optional
from pathlib import Path

class ThreatModeling:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.platform = platform.system().lower()
        self.risk_score = 0
        self.attack_surface = {}
        self.vulnerabilities = []
        self.recommendations = []
        
        # Risk factors and weights
        self.risk_factors = {
            'open_ports': 0.2,
            'running_services': 0.15,
            'user_privileges': 0.25,
            'network_exposure': 0.2,
            'system_configuration': 0.2
        }
    
    def analyze_system(self) -> Dict:
        """Perform comprehensive system threat analysis"""
        try:
            self.logger.info("Starting system threat analysis")
            
            analysis_results = {
                'timestamp': datetime.now(),
                'platform': self.platform,
                'risk_score': 0,
                'attack_surface': {},
                'vulnerabilities': [],
                'recommendations': []
            }
            
            # Analyze different aspects
            port_analysis = self._analyze_open_ports()
            service_analysis = self._analyze_running_services()
            privilege_analysis = self._analyze_user_privileges()
            network_analysis = self._analyze_network_exposure()
            config_analysis = self._analyze_system_configuration()
            
            # Combine results
            analysis_results['attack_surface'] = {
                'open_ports': port_analysis,
                'running_services': service_analysis,
                'user_privileges': privilege_analysis,
                'network_exposure': network_analysis,
                'system_configuration': config_analysis
            }
            
            # Calculate risk score
            analysis_results['risk_score'] = self._calculate_risk_score(analysis_results['attack_surface'])
            
            # Generate vulnerabilities and recommendations
            analysis_results['vulnerabilities'] = self._identify_vulnerabilities(analysis_results['attack_surface'])
            analysis_results['recommendations'] = self._generate_recommendations(analysis_results['vulnerabilities'])
            
            self.attack_surface = analysis_results['attack_surface']
            self.vulnerabilities = analysis_results['vulnerabilities']
            self.recommendations = analysis_results['recommendations']
            self.risk_score = analysis_results['risk_score']
            
            self.logger.info(f"Threat analysis completed. Risk score: {self.risk_score}")
            return analysis_results
            
        except Exception as e:
            self.logger.error(f"Error during threat analysis: {e}")
            return {'error': str(e)}
    
    def _analyze_open_ports(self) -> Dict:
        """Analyze open ports and listening services"""
        try:
            open_ports = []
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'LISTEN' and conn.laddr:
                    port_info = {
                        'port': conn.laddr.port,
                        'protocol': 'TCP' if conn.family == socket.AF_INET else 'UDP',
                        'address': conn.laddr.ip,
                        'process': None
                    }
                    
                    # Try to get process information
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            port_info['process'] = {
                                'pid': conn.pid,
                                'name': proc.name(),
                                'exe': proc.exe()
                            }
                        except psutil.NoSuchProcess:
                            pass
                    
                    open_ports.append(port_info)
            
            # Categorize ports by risk level
            high_risk_ports = [22, 23, 21, 3389, 5900, 5901]  # SSH, Telnet, FTP, RDP, VNC
            medium_risk_ports = [80, 443, 8080, 8443, 3306, 5432]  # HTTP, HTTPS, MySQL, PostgreSQL
            
            risk_analysis = {
                'total_ports': len(open_ports),
                'high_risk_ports': [p for p in open_ports if p['port'] in high_risk_ports],
                'medium_risk_ports': [p for p in open_ports if p['port'] in medium_risk_ports],
                'low_risk_ports': [p for p in open_ports if p['port'] not in high_risk_ports + medium_risk_ports],
                'all_ports': open_ports
            }
            
            return risk_analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing open ports: {e}")
            return {'error': str(e)}
    
    def _analyze_running_services(self) -> Dict:
        """Analyze running system services"""
        try:
            services = []
            
            if self.platform == "windows":
                # Windows services
                try:
                    result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        current_service = {}
                        
                        for line in lines:
                            if 'SERVICE_NAME:' in line:
                                if current_service:
                                    services.append(current_service)
                                current_service = {'name': line.split('SERVICE_NAME:')[1].strip()}
                            elif 'STATE:' in line:
                                current_service['state'] = line.split('STATE:')[1].strip()
                            elif 'START_TYPE:' in line:
                                current_service['start_type'] = line.split('START_TYPE:')[1].strip()
                        
                        if current_service:
                            services.append(current_service)
                            
                except Exception as e:
                    self.logger.warning(f"Could not enumerate Windows services: {e}")
            
            elif self.platform == "linux":
                # Linux services using systemctl
                try:
                    result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines[1:]:  # Skip header
                            if line.strip() and '●' in line:
                                parts = line.split()
                                if len(parts) >= 2:
                                    services.append({
                                        'name': parts[0],
                                        'state': 'running',
                                        'description': ' '.join(parts[1:])
                                    })
                                    
                except Exception as e:
                    self.logger.warning(f"Could not enumerate Linux services: {e}")
            
            # Identify potentially dangerous services
            dangerous_services = [
                'telnet', 'ftp', 'rsh', 'rlogin', 'rexec',
                'tftp', 'xinetd', 'inetd', 'sshd', 'vnc'
            ]
            
            risk_analysis = {
                'total_services': len(services),
                'dangerous_services': [s for s in services if any(ds in s.get('name', '').lower() for ds in dangerous_services)],
                'all_services': services
            }
            
            return risk_analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing running services: {e}")
            return {'error': str(e)}
    
    def _analyze_user_privileges(self) -> Dict:
        """Analyze user privileges and permissions"""
        try:
            privilege_analysis = {
                'current_user': os.getlogin(),
                'is_admin': False,
                'is_root': False,
                'privileged_operations': []
            }
            
            # Check if running as admin/root
            if self.platform == "windows":
                try:
                    import ctypes
                    privilege_analysis['is_admin'] = ctypes.windll.shell32.IsUserAnAdmin()
                except:
                    pass
            elif self.platform == "linux":
                privilege_analysis['is_root'] = os.geteuid() == 0
            
            # Check for privileged operations
            privileged_ops = []
            
            # Check if we can access system directories
            system_dirs = ['/etc', '/var', '/usr/bin'] if self.platform == "linux" else ['C:\\Windows\\System32']
            for sys_dir in system_dirs:
                if os.path.exists(sys_dir):
                    try:
                        os.listdir(sys_dir)
                        privileged_ops.append(f"Can access {sys_dir}")
                    except PermissionError:
                        pass
            
            # Check if we can create files in system directories
            for sys_dir in system_dirs:
                if os.path.exists(sys_dir):
                    try:
                        test_file = os.path.join(sys_dir, '.test_security_suite')
                        with open(test_file, 'w') as f:
                            f.write('test')
                        os.remove(test_file)
                        privileged_ops.append(f"Can write to {sys_dir}")
                    except (PermissionError, OSError):
                        pass
            
            privilege_analysis['privileged_operations'] = privileged_ops
            
            return privilege_analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing user privileges: {e}")
            return {'error': str(e)}
    
    def _analyze_network_exposure(self) -> Dict:
        """Analyze network exposure and connectivity"""
        try:
            network_analysis = {
                'interfaces': [],
                'external_connectivity': False,
                'public_ip': None,
                'network_segments': []
            }
            
            # Get network interfaces
            interfaces = psutil.net_if_addrs()
            for interface, addrs in interfaces.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        network_analysis['interfaces'].append({
                            'interface': interface,
                            'ip': addr.address,
                            'netmask': addr.netmask,
                            'is_private': self._is_private_ip(addr.address)
                        })
            
            # Check external connectivity
            try:
                # Try to get public IP
                import requests
                response = requests.get('https://api.ipify.org', timeout=5)
                if response.status_code == 200:
                    network_analysis['external_connectivity'] = True
                    network_analysis['public_ip'] = response.text
            except:
                pass
            
            # Analyze network segments
            private_networks = []
            public_networks = []
            
            for interface_info in network_analysis['interfaces']:
                if interface_info['is_private']:
                    private_networks.append(interface_info)
                else:
                    public_networks.append(interface_info)
            
            network_analysis['network_segments'] = {
                'private': private_networks,
                'public': public_networks
            }
            
            return network_analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing network exposure: {e}")
            return {'error': str(e)}
    
    def _analyze_system_configuration(self) -> Dict:
        """Analyze system security configuration"""
        try:
            config_analysis = {
                'firewall_status': 'unknown',
                'antivirus_status': 'unknown',
                'updates_status': 'unknown',
                'security_settings': {}
            }
            
            # Check firewall status
            if self.platform == "windows":
                try:
                    result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        if 'ON' in result.stdout:
                            config_analysis['firewall_status'] = 'enabled'
                        else:
                            config_analysis['firewall_status'] = 'disabled'
                except:
                    pass
            
            elif self.platform == "linux":
                try:
                    result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout.strip():
                        config_analysis['firewall_status'] = 'enabled'
                    else:
                        config_analysis['firewall_status'] = 'disabled'
                except:
                    pass
            
            # Check for antivirus (simplified)
            antivirus_processes = [
                'avast', 'avg', 'mcafee', 'norton', 'kaspersky',
                'bitdefender', 'malwarebytes', 'windows defender'
            ]
            
            running_av = []
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    for av_name in antivirus_processes:
                        if av_name in proc_name:
                            running_av.append(proc_name)
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if running_av:
                config_analysis['antivirus_status'] = 'detected'
                config_analysis['security_settings']['antivirus_processes'] = running_av
            else:
                config_analysis['antivirus_status'] = 'not_detected'
            
            return config_analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing system configuration: {e}")
            return {'error': str(e)}
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            # Fallback for older Python versions
            private_ranges = [
                ('10.0.0.0', '10.255.255.255'),
                ('172.16.0.0', '172.31.255.255'),
                ('192.168.0.0', '192.168.255.255')
            ]
            
            ip_parts = [int(x) for x in ip.split('.')]
            
            for start, end in private_ranges:
                start_parts = [int(x) for x in start.split('.')]
                end_parts = [int(x) for x in end.split('.')]
                
                if all(start_parts[i] <= ip_parts[i] <= end_parts[i] for i in range(4)):
                    return True
            
            return False
    
    def _calculate_risk_score(self, attack_surface: Dict) -> float:
        """Calculate overall risk score based on attack surface"""
        try:
            risk_score = 0.0
            
            # Port risk
            port_analysis = attack_surface.get('open_ports', {})
            high_risk_ports = len(port_analysis.get('high_risk_ports', []))
            medium_risk_ports = len(port_analysis.get('medium_risk_ports', []))
            
            risk_score += high_risk_ports * 0.3
            risk_score += medium_risk_ports * 0.15
            
            # Service risk
            service_analysis = attack_surface.get('running_services', {})
            dangerous_services = len(service_analysis.get('dangerous_services', []))
            risk_score += dangerous_services * 0.2
            
            # Privilege risk
            privilege_analysis = attack_surface.get('user_privileges', {})
            if privilege_analysis.get('is_admin') or privilege_analysis.get('is_root'):
                risk_score += 0.3
            
            privileged_ops = len(privilege_analysis.get('privileged_operations', []))
            risk_score += privileged_ops * 0.1
            
            # Network risk
            network_analysis = attack_surface.get('network_exposure', {})
            if network_analysis.get('external_connectivity'):
                risk_score += 0.2
            
            public_networks = len(network_analysis.get('network_segments', {}).get('public', []))
            risk_score += public_networks * 0.15
            
            # Configuration risk
            config_analysis = attack_surface.get('system_configuration', {})
            if config_analysis.get('firewall_status') == 'disabled':
                risk_score += 0.25
            
            if config_analysis.get('antivirus_status') == 'not_detected':
                risk_score += 0.2
            
            # Normalize to 0-100 scale
            risk_score = min(100, risk_score * 100)
            
            return round(risk_score, 2)
            
        except Exception as e:
            self.logger.error(f"Error calculating risk score: {e}")
            return 0.0
    
    def _identify_vulnerabilities(self, attack_surface: Dict) -> List[Dict]:
        """Identify specific vulnerabilities based on attack surface"""
        vulnerabilities = []
        
        try:
            # Port vulnerabilities
            port_analysis = attack_surface.get('open_ports', {})
            for port_info in port_analysis.get('high_risk_ports', []):
                vulnerabilities.append({
                    'type': 'HIGH_RISK_PORT',
                    'description': f"High-risk port {port_info['port']} is open",
                    'severity': 'HIGH',
                    'port': port_info['port'],
                    'process': port_info.get('process', {}).get('name', 'Unknown')
                })
            
            # Service vulnerabilities
            service_analysis = attack_surface.get('running_services', {})
            for service in service_analysis.get('dangerous_services', []):
                vulnerabilities.append({
                    'type': 'DANGEROUS_SERVICE',
                    'description': f"Dangerous service running: {service.get('name', 'Unknown')}",
                    'severity': 'HIGH',
                    'service_name': service.get('name', 'Unknown')
                })
            
            # Privilege vulnerabilities
            privilege_analysis = attack_surface.get('user_privileges', {})
            if privilege_analysis.get('is_admin') or privilege_analysis.get('is_root'):
                vulnerabilities.append({
                    'type': 'ELEVATED_PRIVILEGES',
                    'description': "Running with elevated privileges",
                    'severity': 'MEDIUM',
                    'user': privilege_analysis.get('current_user', 'Unknown')
                })
            
            # Network vulnerabilities
            network_analysis = attack_surface.get('network_exposure', {})
            if network_analysis.get('external_connectivity'):
                vulnerabilities.append({
                    'type': 'EXTERNAL_CONNECTIVITY',
                    'description': "System has external network connectivity",
                    'severity': 'MEDIUM',
                    'public_ip': network_analysis.get('public_ip', 'Unknown')
                })
            
            # Configuration vulnerabilities
            config_analysis = attack_surface.get('system_configuration', {})
            if config_analysis.get('firewall_status') == 'disabled':
                vulnerabilities.append({
                    'type': 'FIREWALL_DISABLED',
                    'description': "Firewall is disabled",
                    'severity': 'HIGH'
                })
            
            if config_analysis.get('antivirus_status') == 'not_detected':
                vulnerabilities.append({
                    'type': 'NO_ANTIVIRUS',
                    'description': "No antivirus software detected",
                    'severity': 'HIGH'
                })
            
        except Exception as e:
            self.logger.error(f"Error identifying vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        try:
            for vuln in vulnerabilities:
                if vuln['type'] == 'HIGH_RISK_PORT':
                    recommendations.append({
                        'type': 'PORT_SECURITY',
                        'description': f"Close or restrict access to port {vuln['port']}",
                        'priority': 'HIGH',
                        'action': f"Configure firewall to block port {vuln['port']}"
                    })
                
                elif vuln['type'] == 'DANGEROUS_SERVICE':
                    recommendations.append({
                        'type': 'SERVICE_SECURITY',
                        'description': f"Disable or secure service: {vuln['service_name']}",
                        'priority': 'HIGH',
                        'action': f"Disable service {vuln['service_name']} if not needed"
                    })
                
                elif vuln['type'] == 'FIREWALL_DISABLED':
                    recommendations.append({
                        'type': 'FIREWALL_ENABLE',
                        'description': "Enable system firewall",
                        'priority': 'HIGH',
                        'action': "Enable Windows Firewall or configure iptables"
                    })
                
                elif vuln['type'] == 'NO_ANTIVIRUS':
                    recommendations.append({
                        'type': 'ANTIVIRUS_INSTALL',
                        'description': "Install antivirus software",
                        'priority': 'HIGH',
                        'action': "Install and configure antivirus software"
                    })
                
                elif vuln['type'] == 'EXTERNAL_CONNECTIVITY':
                    recommendations.append({
                        'type': 'NETWORK_SECURITY',
                        'description': "Implement network security measures",
                        'priority': 'MEDIUM',
                        'action': "Use VPN, configure firewall rules, monitor network traffic"
                    })
            
            # Add general recommendations
            recommendations.extend([
                {
                    'type': 'GENERAL_SECURITY',
                    'description': "Keep system and software updated",
                    'priority': 'MEDIUM',
                    'action': "Enable automatic updates and regularly check for patches"
                },
                {
                    'type': 'USER_EDUCATION',
                    'description': "Implement security awareness training",
                    'priority': 'MEDIUM',
                    'action': "Train users on security best practices and phishing awareness"
                }
            ])
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
        
        return recommendations
    
    def get_risk_assessment(self) -> Dict:
        """Get current risk assessment"""
        return {
            'risk_score': self.risk_score,
            'attack_surface': self.attack_surface,
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self.recommendations,
            'last_updated': datetime.now()
        } 