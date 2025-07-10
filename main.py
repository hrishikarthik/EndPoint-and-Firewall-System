#!/usr/bin/env python3
"""
Cross-Platform Security Suite
Firewall + EDR + Threat Modeling + Malicious Activity Detection
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import sys
import os
import logging
from datetime import datetime

# Import our security modules
from modules.firewall import FirewallManager
from modules.edr import EDRManager
from modules.threat_modeling import ThreatModeling
from modules.malicious_detection import MaliciousDetection
from modules.virustotal import VirusTotalAPI
from modules.gui import SecurityGUI

class SecuritySuite:
    def __init__(self):
        self.setup_logging()
        self.root = tk.Tk()
        self.root.title("Security Suite - Firewall & EDR")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Initialize security modules
        self.firewall = FirewallManager()
        self.edr = EDRManager()
        self.threat_modeling = ThreatModeling()
        self.malicious_detection = MaliciousDetection()
        self.virustotal = VirusTotalAPI()
        
        # Initialize GUI
        self.gui = SecurityGUI(self.root, self)
        
        # Start monitoring threads
        self.start_monitoring()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_suite.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def start_monitoring(self):
        """Start all monitoring threads"""
        try:
            # Start firewall monitoring
            firewall_thread = threading.Thread(target=self.firewall.start_monitoring, daemon=True)
            firewall_thread.start()
            
            # Start EDR monitoring
            edr_thread = threading.Thread(target=self.edr.start_monitoring, daemon=True)
            edr_thread.start()
            
            # Start malicious activity detection
            malicious_thread = threading.Thread(target=self.malicious_detection.start_monitoring, daemon=True)
            malicious_thread.start()
            
            self.logger.info("All monitoring threads started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting monitoring threads: {e}")
            messagebox.showerror("Error", f"Failed to start monitoring: {e}")
    
    def run(self):
        """Start the application"""
        try:
            self.logger.info("Starting Security Suite application")
            self.root.mainloop()
        except KeyboardInterrupt:
            self.logger.info("Application interrupted by user")
        except Exception as e:
            self.logger.error(f"Application error: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Cleanup resources before exit"""
        try:
            self.firewall.stop_monitoring()
            self.edr.stop_monitoring()
            self.malicious_detection.stop_monitoring()
            self.logger.info("Cleanup completed")
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")

def main():
    """Main entry point"""
    try:
        app = SecuritySuite()
        app.run()
    except Exception as e:
        print(f"Failed to start application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 