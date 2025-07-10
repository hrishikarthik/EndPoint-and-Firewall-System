"""
GUI Module - Modern interface for the Security Suite
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog
import threading
import time
from datetime import datetime
from typing import Dict, List

class SecurityGUI:
    def __init__(self, root: tk.Tk, security_suite):
        self.root = root
        self.security_suite = security_suite
        self.setup_styles()
        self.create_widgets()
        self.start_update_thread()
    
    def setup_styles(self):
        """Setup modern styling"""
        style = ttk.Style()
        
        # Configure colors
        self.colors = {
            'bg_dark': '#2b2b2b',
            'bg_medium': '#3c3c3c',
            'bg_light': '#4a4a4a',
            'text_light': '#ffffff',
            'text_gray': '#cccccc',
            'accent': '#007acc',
            'success': '#28a745',
            'warning': '#ffc107',
            'danger': '#dc3545',
            'info': '#17a2b8'
        }
        
        # Configure styles
        style.theme_use('clam')
        style.configure('TFrame', background=self.colors['bg_dark'])
        style.configure('TLabel', background=self.colors['bg_dark'], foreground=self.colors['text_light'])
        style.configure('TButton', background=self.colors['accent'], foreground=self.colors['text_light'])
        style.configure('Header.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Status.TLabel', font=('Arial', 10))
        
        self.root.configure(bg=self.colors['bg_dark'])
    
    def create_widgets(self):
        """Create the main GUI widgets"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_firewall_tab()
        self.create_edr_tab()
        self.create_threat_modeling_tab()
        self.create_malicious_detection_tab()
        self.create_virustotal_tab()
        self.create_logs_tab()
    
    def create_dashboard_tab(self):
        """Create the main dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Header
        header_frame = ttk.Frame(dashboard_frame)
        header_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(header_frame, text="Security Suite Dashboard", style='Header.TLabel').pack(side='left')
        
        # Status indicators
        status_frame = ttk.Frame(dashboard_frame)
        status_frame.pack(fill='x', padx=20, pady=10)
        
        # Create status cards
        self.create_status_card(status_frame, "Firewall", "Active", "success", 0, 0)
        self.create_status_card(status_frame, "EDR", "Active", "success", 0, 1)
        self.create_status_card(status_frame, "Threat Modeling", "Active", "success", 0, 2)
        self.create_status_card(status_frame, "Malicious Detection", "Active", "success", 1, 0)
        self.create_status_card(status_frame, "VirusTotal", "Ready", "info", 1, 1)
        self.create_status_card(status_frame, "Risk Score", "0", "warning", 1, 2)
        
        # Recent alerts
        alerts_frame = ttk.Frame(dashboard_frame)
        alerts_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        ttk.Label(alerts_frame, text="Recent Alerts", style='Header.TLabel').pack(anchor='w')
        
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=('Time', 'Type', 'Severity', 'Description'), show='headings')
        self.alerts_tree.heading('Time', text='Time')
        self.alerts_tree.heading('Type', text='Type')
        self.alerts_tree.heading('Severity', text='Severity')
        self.alerts_tree.heading('Description', text='Description')
        
        self.alerts_tree.column('Time', width=150)
        self.alerts_tree.column('Type', width=100)
        self.alerts_tree.column('Severity', width=80)
        self.alerts_tree.column('Description', width=300)
        
        alerts_scrollbar = ttk.Scrollbar(alerts_frame, orient='vertical', command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=alerts_scrollbar.set)
        
        self.alerts_tree.pack(side='left', fill='both', expand=True)
        alerts_scrollbar.pack(side='right', fill='y')
    
    def create_status_card(self, parent, title, status, color, row, col):
        """Create a status indicator card"""
        card_frame = ttk.Frame(parent)
        card_frame.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
        
        ttk.Label(card_frame, text=title, style='Header.TLabel').pack()
        status_label = ttk.Label(card_frame, text=status, foreground=self.colors[color])
        status_label.pack()
        
        # Store reference for updates
        if not hasattr(self, 'status_labels'):
            self.status_labels = {}
        self.status_labels[title] = status_label
    
    def create_firewall_tab(self):
        """Create the firewall tab"""
        firewall_frame = ttk.Frame(self.notebook)
        self.notebook.add(firewall_frame, text="Firewall")
        
        # Controls
        controls_frame = ttk.Frame(firewall_frame)
        controls_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Button(controls_frame, text="Block IP", command=self.block_ip_dialog).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Unblock IP", command=self.unblock_ip_dialog).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Refresh", command=self.refresh_firewall).pack(side='left', padx=5)
        
        # Statistics
        stats_frame = ttk.Frame(firewall_frame)
        stats_frame.pack(fill='x', padx=20, pady=10)
        
        self.firewall_stats_label = ttk.Label(stats_frame, text="Loading statistics...")
        self.firewall_stats_label.pack()
        
        # Connections table
        connections_frame = ttk.Frame(firewall_frame)
        connections_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        ttk.Label(connections_frame, text="Active Connections", style='Header.TLabel').pack(anchor='w')
        
        self.connections_tree = ttk.Treeview(connections_frame, 
                                           columns=('Local', 'Remote', 'Status', 'Process'),
                                           show='headings')
        self.connections_tree.heading('Local', text='Local Address')
        self.connections_tree.heading('Remote', text='Remote Address')
        self.connections_tree.heading('Status', text='Status')
        self.connections_tree.heading('Process', text='Process')
        
        self.connections_tree.column('Local', width=150)
        self.connections_tree.column('Remote', width=150)
        self.connections_tree.column('Status', width=80)
        self.connections_tree.column('Process', width=150)
        
        connections_scrollbar = ttk.Scrollbar(connections_frame, orient='vertical', command=self.connections_tree.yview)
        self.connections_tree.configure(yscrollcommand=connections_scrollbar.set)
        
        self.connections_tree.pack(side='left', fill='both', expand=True)
        connections_scrollbar.pack(side='right', fill='y')
    
    def create_edr_tab(self):
        """Create the EDR tab"""
        edr_frame = ttk.Frame(self.notebook)
        self.notebook.add(edr_frame, text="EDR")
        
        # Controls
        controls_frame = ttk.Frame(edr_frame)
        controls_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Button(controls_frame, text="Kill Process", command=self.kill_process_dialog).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Quarantine File", command=self.quarantine_file_dialog).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Refresh", command=self.refresh_edr).pack(side='left', padx=5)
        
        # Statistics
        stats_frame = ttk.Frame(edr_frame)
        stats_frame.pack(fill='x', padx=20, pady=10)
        
        self.edr_stats_label = ttk.Label(stats_frame, text="Loading statistics...")
        self.edr_stats_label.pack()
        
        # Processes table
        processes_frame = ttk.Frame(edr_frame)
        processes_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        ttk.Label(processes_frame, text="Running Processes", style='Header.TLabel').pack(anchor='w')
        
        self.processes_tree = ttk.Treeview(processes_frame, 
                                          columns=('PID', 'Name', 'CPU', 'Memory', 'Status'),
                                          show='headings')
        self.processes_tree.heading('PID', text='PID')
        self.processes_tree.heading('Name', text='Name')
        self.processes_tree.heading('CPU', text='CPU %')
        self.processes_tree.heading('Memory', text='Memory %')
        self.processes_tree.heading('Status', text='Status')
        
        self.processes_tree.column('PID', width=80)
        self.processes_tree.column('Name', width=200)
        self.processes_tree.column('CPU', width=80)
        self.processes_tree.column('Memory', width=100)
        self.processes_tree.column('Status', width=100)
        
        processes_scrollbar = ttk.Scrollbar(processes_frame, orient='vertical', command=self.processes_tree.yview)
        self.processes_tree.configure(yscrollcommand=processes_scrollbar.set)
        
        self.processes_tree.pack(side='left', fill='both', expand=True)
        processes_scrollbar.pack(side='right', fill='y')
    
    def create_threat_modeling_tab(self):
        """Create the threat modeling tab"""
        threat_frame = ttk.Frame(self.notebook)
        self.notebook.add(threat_frame, text="Threat Modeling")
        
        # Risk score display
        risk_frame = ttk.Frame(threat_frame)
        risk_frame.pack(fill='x', padx=20, pady=10)
        
        self.risk_score_label = ttk.Label(risk_frame, text="Risk Score: Calculating...", style='Header.TLabel')
        self.risk_score_label.pack()
        
        # Analysis button
        ttk.Button(risk_frame, text="Run Threat Analysis", command=self.run_threat_analysis).pack(pady=10)
        
        # Results
        results_frame = ttk.Frame(threat_frame)
        results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Vulnerabilities
        vuln_frame = ttk.Frame(results_frame)
        vuln_frame.pack(fill='both', expand=True)
        
        ttk.Label(vuln_frame, text="Vulnerabilities", style='Header.TLabel').pack(anchor='w')
        
        self.vulnerabilities_tree = ttk.Treeview(vuln_frame, 
                                               columns=('Type', 'Severity', 'Description'),
                                               show='headings')
        self.vulnerabilities_tree.heading('Type', text='Type')
        self.vulnerabilities_tree.heading('Severity', text='Severity')
        self.vulnerabilities_tree.heading('Description', text='Description')
        
        self.vulnerabilities_tree.column('Type', width=150)
        self.vulnerabilities_tree.column('Severity', width=100)
        self.vulnerabilities_tree.column('Description', width=300)
        
        vuln_scrollbar = ttk.Scrollbar(vuln_frame, orient='vertical', command=self.vulnerabilities_tree.yview)
        self.vulnerabilities_tree.configure(yscrollcommand=vuln_scrollbar.set)
        
        self.vulnerabilities_tree.pack(side='left', fill='both', expand=True)
        vuln_scrollbar.pack(side='right', fill='y')
    
    def create_malicious_detection_tab(self):
        """Create the malicious detection tab"""
        detection_frame = ttk.Frame(self.notebook)
        self.notebook.add(detection_frame, text="Malicious Detection")
        
        # Statistics
        stats_frame = ttk.Frame(detection_frame)
        stats_frame.pack(fill='x', padx=20, pady=10)
        
        self.detection_stats_label = ttk.Label(stats_frame, text="Loading statistics...")
        self.detection_stats_label.pack()
        
        # Detections table
        detections_frame = ttk.Frame(detection_frame)
        detections_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        ttk.Label(detections_frame, text="Recent Detections", style='Header.TLabel').pack(anchor='w')
        
        self.detections_tree = ttk.Treeview(detections_frame, 
                                           columns=('Time', 'Type', 'Severity', 'Description'),
                                           show='headings')
        self.detections_tree.heading('Time', text='Time')
        self.detections_tree.heading('Type', text='Type')
        self.detections_tree.heading('Severity', text='Severity')
        self.detections_tree.heading('Description', text='Description')
        
        self.detections_tree.column('Time', width=150)
        self.detections_tree.column('Type', width=150)
        self.detections_tree.column('Severity', width=100)
        self.detections_tree.column('Description', width=300)
        
        detections_scrollbar = ttk.Scrollbar(detections_frame, orient='vertical', command=self.detections_tree.yview)
        self.detections_tree.configure(yscrollcommand=detections_scrollbar.set)
        
        self.detections_tree.pack(side='left', fill='both', expand=True)
        detections_scrollbar.pack(side='right', fill='y')
    
    def create_virustotal_tab(self):
        """Create the VirusTotal tab"""
        vt_frame = ttk.Frame(self.notebook)
        self.notebook.add(vt_frame, text="VirusTotal")
        
        # API key setup
        api_frame = ttk.Frame(vt_frame)
        api_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(api_frame, text="VirusTotal API Key:").pack(side='left')
        self.api_key_entry = ttk.Entry(api_frame, width=50, show='*')
        self.api_key_entry.pack(side='left', padx=5)
        ttk.Button(api_frame, text="Set API Key", command=self.set_api_key).pack(side='left', padx=5)
        
        # Scan controls
        scan_frame = ttk.Frame(vt_frame)
        scan_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Button(scan_frame, text="Scan File", command=self.scan_file_dialog).pack(side='left', padx=5)
        ttk.Button(scan_frame, text="Scan URL", command=self.scan_url_dialog).pack(side='left', padx=5)
        
        # Results
        results_frame = ttk.Frame(vt_frame)
        results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        ttk.Label(results_frame, text="Scan Results", style='Header.TLabel').pack(anchor='w')
        
        self.vt_results_text = scrolledtext.ScrolledText(results_frame, height=20)
        self.vt_results_text.pack(fill='both', expand=True)
    
    def create_logs_tab(self):
        """Create the logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")
        
        # Log display
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=30)
        self.logs_text.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Load initial logs
        self.load_logs()
    
    def start_update_thread(self):
        """Start the update thread for real-time updates"""
        def update_loop():
            while True:
                try:
                    self.root.after(0, self.update_dashboard)
                    time.sleep(2)  # Update every 2 seconds
                except Exception as e:
                    print(f"Error in update loop: {e}")
                    time.sleep(5)
        
        update_thread = threading.Thread(target=update_loop, daemon=True)
        update_thread.start()
    
    def update_dashboard(self):
        """Update dashboard with current data"""
        try:
            # Update firewall stats
            firewall_stats = self.security_suite.firewall.get_connection_stats()
            self.status_labels["Firewall"].config(text=f"{firewall_stats['total_connections']} connections")
            
            # Update EDR stats
            edr_stats = self.security_suite.edr.get_edr_stats()
            self.status_labels["EDR"].config(text=f"{edr_stats['total_processes']} processes")
            
            # Update malicious detection stats
            detection_stats = self.security_suite.malicious_detection.get_detection_stats()
            self.status_labels["Malicious Detection"].config(text=f"{detection_stats['suspicious_activities']} alerts")
            
            # Update risk score
            threat_assessment = self.security_suite.threat_modeling.get_risk_assessment()
            risk_score = threat_assessment['risk_score']
            self.status_labels["Risk Score"].config(text=f"{risk_score}")
            
            # Update alerts
            self.update_alerts()
            
        except Exception as e:
            print(f"Error updating dashboard: {e}")
    
    def update_alerts(self):
        """Update the alerts tree"""
        try:
            # Clear existing items
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            
            # Get recent alerts from all modules
            all_alerts = []
            
            # Firewall alerts
            firewall_alerts = self.security_suite.firewall.get_recent_alerts(5)
            for alert in firewall_alerts:
                all_alerts.append({
                    'time': alert['timestamp'].strftime('%H:%M:%S'),
                    'type': 'Firewall',
                    'severity': alert['severity'],
                    'description': f"Suspicious connection: {alert['remote_addr']}"
                })
            
            # EDR alerts
            edr_alerts = self.security_suite.edr.get_recent_alerts(5)
            for alert in edr_alerts:
                all_alerts.append({
                    'time': alert['timestamp'].strftime('%H:%M:%S'),
                    'type': 'EDR',
                    'severity': alert['severity'],
                    'description': f"Suspicious process: {alert.get('name', 'Unknown')}"
                })
            
            # Malicious detection alerts
            detection_alerts = self.security_suite.malicious_detection.get_recent_detections(5)
            for alert in detection_alerts:
                all_alerts.append({
                    'time': alert['timestamp'].strftime('%H:%M:%S'),
                    'type': 'Detection',
                    'severity': alert['severity'],
                    'description': f"{alert['type']}: {alert.get('description', 'Unknown')}"
                })
            
            # Sort by time and add to tree
            all_alerts.sort(key=lambda x: x['time'], reverse=True)
            
            for alert in all_alerts[:10]:  # Show last 10 alerts
                self.alerts_tree.insert('', 'end', values=(
                    alert['time'],
                    alert['type'],
                    alert['severity'],
                    alert['description']
                ))
                
        except Exception as e:
            print(f"Error updating alerts: {e}")
    
    # Dialog methods
    def block_ip_dialog(self):
        """Show dialog to block an IP"""
        ip = simpledialog.askstring("Block IP", "Enter IP address to block:")
        if ip:
            self.security_suite.firewall.block_ip(ip)
            messagebox.showinfo("Success", f"IP {ip} has been blocked")
    
    def unblock_ip_dialog(self):
        """Show dialog to unblock an IP"""
        ip = simpledialog.askstring("Unblock IP", "Enter IP address to unblock:")
        if ip:
            self.security_suite.firewall.unblock_ip(ip)
            messagebox.showinfo("Success", f"IP {ip} has been unblocked")
    
    def kill_process_dialog(self):
        """Show dialog to kill a process"""
        pid = simpledialog.askinteger("Kill Process", "Enter PID to kill:")
        if pid:
            if self.security_suite.edr.kill_suspicious_process(pid):
                messagebox.showinfo("Success", f"Process {pid} has been terminated")
            else:
                messagebox.showerror("Error", f"Failed to kill process {pid}")
    
    def quarantine_file_dialog(self):
        """Show dialog to quarantine a file"""
        file_path = filedialog.askopenfilename(title="Select file to quarantine")
        if file_path:
            if self.security_suite.edr.quarantine_file(file_path):
                messagebox.showinfo("Success", f"File {file_path} has been quarantined")
            else:
                messagebox.showerror("Error", f"Failed to quarantine file {file_path}")
    
    def set_api_key(self):
        """Set VirusTotal API key"""
        api_key = self.api_key_entry.get()
        if api_key:
            self.security_suite.virustotal.set_api_key(api_key)
            messagebox.showinfo("Success", "VirusTotal API key has been set")
        else:
            messagebox.showerror("Error", "Please enter an API key")
    
    def scan_file_dialog(self):
        """Show dialog to scan a file"""
        file_path = filedialog.askopenfilename(title="Select file to scan")
        if file_path:
            self.scan_file_with_vt(file_path)
    
    def scan_url_dialog(self):
        """Show dialog to scan a URL"""
        url = simpledialog.askstring("Scan URL", "Enter URL to scan:")
        if url:
            self.scan_url_with_vt(url)
    
    def scan_file_with_vt(self, file_path):
        """Scan file with VirusTotal"""
        try:
            self.vt_results_text.delete(1.0, tk.END)
            self.vt_results_text.insert(tk.END, f"Scanning file: {file_path}\n")
            self.vt_results_text.insert(tk.END, "Please wait...\n")
            self.root.update()
            
            result = self.security_suite.virustotal.analyze_file(file_path)
            
            self.vt_results_text.delete(1.0, tk.END)
            self.vt_results_text.insert(tk.END, f"Scan Results for: {file_path}\n")
            self.vt_results_text.insert(tk.END, "=" * 50 + "\n\n")
            
            for key, value in result.items():
                self.vt_results_text.insert(tk.END, f"{key}: {value}\n")
                
        except Exception as e:
            self.vt_results_text.delete(1.0, tk.END)
            self.vt_results_text.insert(tk.END, f"Error scanning file: {e}")
    
    def scan_url_with_vt(self, url):
        """Scan URL with VirusTotal"""
        try:
            self.vt_results_text.delete(1.0, tk.END)
            self.vt_results_text.insert(tk.END, f"Scanning URL: {url}\n")
            self.vt_results_text.insert(tk.END, "Please wait...\n")
            self.root.update()
            
            result = self.security_suite.virustotal.analyze_url(url)
            
            self.vt_results_text.delete(1.0, tk.END)
            self.vt_results_text.insert(tk.END, f"Scan Results for: {url}\n")
            self.vt_results_text.insert(tk.END, "=" * 50 + "\n\n")
            
            for key, value in result.items():
                self.vt_results_text.insert(tk.END, f"{key}: {value}\n")
                
        except Exception as e:
            self.vt_results_text.delete(1.0, tk.END)
            self.vt_results_text.insert(tk.END, f"Error scanning URL: {e}")
    
    def run_threat_analysis(self):
        """Run threat analysis"""
        try:
            self.risk_score_label.config(text="Risk Score: Analyzing...")
            self.root.update()
            
            result = self.security_suite.threat_modeling.analyze_system()
            
            # Update risk score
            risk_score = result.get('risk_score', 0)
            self.risk_score_label.config(text=f"Risk Score: {risk_score}")
            
            # Update vulnerabilities
            self.vulnerabilities_tree.delete(*self.vulnerabilities_tree.get_children())
            for vuln in result.get('vulnerabilities', []):
                self.vulnerabilities_tree.insert('', 'end', values=(
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'Unknown'),
                    vuln.get('description', 'Unknown')
                ))
                
            messagebox.showinfo("Success", "Threat analysis completed")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run threat analysis: {e}")
    
    def refresh_firewall(self):
        """Refresh firewall data"""
        try:
            stats = self.security_suite.firewall.get_connection_stats()
            self.firewall_stats_label.config(text=f"Connections: {stats['total_connections']}, Blocked IPs: {stats['blocked_ips']}")
            
            # Update connections tree
            self.connections_tree.delete(*self.connections_tree.get_children())
            for conn_key, conn_data in self.security_suite.firewall.connections.items():
                self.connections_tree.insert('', 'end', values=(
                    conn_data['local_addr'],
                    conn_data['remote_addr'],
                    conn_data['status'],
                    f"PID: {conn_data['pid']}" if conn_data['pid'] else 'Unknown'
                ))
                
        except Exception as e:
            print(f"Error refreshing firewall: {e}")
    
    def refresh_edr(self):
        """Refresh EDR data"""
        try:
            stats = self.security_suite.edr.get_edr_stats()
            self.edr_stats_label.config(text=f"Processes: {stats['total_processes']}, Suspicious: {stats['suspicious_processes']}")
            
            # Update processes tree
            self.processes_tree.delete(*self.processes_tree.get_children())
            for pid, proc_data in self.security_suite.edr.processes.items():
                self.processes_tree.insert('', 'end', values=(
                    pid,
                    proc_data['name'],
                    f"{proc_data['cpu_percent']:.1f}",
                    f"{proc_data['memory_percent']:.1f}",
                    "Running"
                ))
                
        except Exception as e:
            print(f"Error refreshing EDR: {e}")
    
    def load_logs(self):
        """Load and display logs"""
        try:
            with open('security_suite.log', 'r') as f:
                logs = f.read()
                self.logs_text.delete(1.0, tk.END)
                self.logs_text.insert(tk.END, logs)
        except FileNotFoundError:
            self.logs_text.insert(tk.END, "No log file found.")
        except Exception as e:
            self.logs_text.insert(tk.END, f"Error loading logs: {e}") 