#!/usr/bin/env python3
"""
Security Suite Launcher
Simple launcher with error handling and setup checks
"""

import sys
import os
import subprocess
import platform

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    return True

def check_dependencies():
    """Check if required dependencies are installed"""
    required_modules = [
        'tkinter', 'psutil', 'requests', 'threading', 'logging',
        'datetime', 'hashlib', 'json', 'socket', 'subprocess'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print("❌ Missing required modules:")
        for module in missing_modules:
            print(f"  - {module}")
        print("\nPlease install dependencies:")
        print("pip install -r requirements.txt")
        return False
    
    return True

def check_permissions():
    """Check if running with appropriate permissions"""
    system = platform.system().lower()
    
    if system == "windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("⚠️  Warning: Not running as administrator")
                print("Some firewall features may not work properly")
                return True  # Continue anyway
        except:
            pass
    elif system == "linux":
        if os.geteuid() != 0:
            print("⚠️  Warning: Not running as root")
            print("Some firewall features may not work properly")
            return True  # Continue anyway
    
    return True

def setup_environment():
    """Setup the environment for the security suite"""
    print("🔧 Setting up Security Suite environment...")
    
    # Create necessary directories
    os.makedirs('.security_quarantine', exist_ok=True)
    
    # Check if log file exists, create if not
    if not os.path.exists('security_suite.log'):
        with open('security_suite.log', 'w') as f:
            f.write(f"Security Suite Log - Started at {os.popen('date').read().strip()}\n")
    
    print("✅ Environment setup complete")

def main():
    """Main launcher function"""
    print("🛡️  Security Suite - Firewall & EDR")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check permissions
    if not check_permissions():
        sys.exit(1)
    
    # Setup environment
    setup_environment()
    
    print("\n🚀 Starting Security Suite...")
    print("=" * 50)
    
    try:
        # Import and run the main application
        from main import main as run_security_suite
        run_security_suite()
    except KeyboardInterrupt:
        print("\n⚠️  Application interrupted by user")
    except Exception as e:
        print(f"\n❌ Error starting Security Suite: {e}")
        print("\nTroubleshooting:")
        print("1. Ensure all dependencies are installed: pip install -r requirements.txt")
        print("2. Check if you have appropriate permissions")
        print("3. Review the logs for more details")
        sys.exit(1)

if __name__ == "__main__":
    main() 