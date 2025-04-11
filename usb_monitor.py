import os
import hashlib
import psutil
import time
import logging
import ctypes

# Setup logging
logging.basicConfig(filename="usb_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# Malicious file hashes (Add real ones)
MALICIOUS_HASHES = {
    "5d41402abc4b2a76b9719d911017c592",  # Example MD5 hash
}

# Folder to quarantine infected files
QUARANTINE_FOLDER = "quarantine"
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

def get_usb_devices():
    """Returns a list of connected USB drives."""
    drives = []
    partitions = psutil.disk_partitions()
    
    for partition in partitions:
        if "removable" in partition.opts or partition.device.startswith("/dev/sd"):
            drives.append(partition.mountpoint)
    
    return drives

def get_file_hash(filepath):
    """Returns the MD5 hash of a file."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception:
        return None

def list_usb_files(usb_path):
    """Lists all files in the USB device."""
    print(f"\n📂 Files in {usb_path}:")
    logging.info(f"📂 Listing files in {usb_path}")

    file_list = []
    for root, _, files in os.walk(usb_path):
        for file in files:
            file_list.append(os.path.join(root, file))

    for idx, file in enumerate(file_list, 1):
        print(f"  {idx}. {file}")

    return file_list

def scan_usb(usb_path):
    """Scans USB for known malware and prompts user for approval."""
    logging.info(f"🔍 Scanning USB: {usb_path}")
    
    print("\n🔍 Scanning USB for malware...")
    infected_files = []
    
    for root, _, files in os.walk(usb_path):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = get_file_hash(filepath)

            if file_hash in MALICIOUS_HASHES:
                infected_files.append(filepath)

    if infected_files:
        print("⚠️ Malicious files found:")
        for file in infected_files:
            print(f"  ❌ {file}")
            os.rename(file, os.path.join(QUARANTINE_FOLDER, os.path.basename(file)))
            logging.warning(f"⚠️ Malicious file quarantined: {file}")

    # Show all USB files to user
    list_usb_files(usb_path)

    # Ask user to approve/reject USB
    decision = input("\n🔒 Do you want to allow this USB? (yes/no): ").strip().lower()
    
    if decision != "yes":
        block_usb(usb_path)
        logging.warning(f"🚫 USB access blocked: {usb_path}")
        print("\n🚫 USB access has been blocked!")
    else:
        logging.info(f"✅ USB allowed: {usb_path}")
        print("\n✅ USB access granted!")

def block_usb(usb_path):
    """Blocks access to a USB drive."""
    try:
        if os.name == "nt":  # Windows
            ctypes.windll.kernel32.SetVolumeMountPointW(usb_path, None)
        else:  # Linux
            os.system(f"umount {usb_path}")

        logging.warning(f"🚫 USB {usb_path} has been blocked.")
    except Exception as e:
        logging.error(f"❌ Failed to block USB: {str(e)}")

def monitor_usb():
    """Continuously monitors USB insertions."""
    known_devices = set(get_usb_devices())

    while True:
        current_devices = set(get_usb_devices())
        
        # Detect newly inserted USB
        new_devices = current_devices - known_devices
        if new_devices:
            for usb in new_devices:
                logging.info(f"🔌 USB Inserted: {usb}")
                print(f"\n🔌 New USB detected: {usb}")
                scan_usb(usb)

        known_devices = current_devices
        time.sleep(5)  # Check every 5 seconds

if __name__ == "__main__":
    logging.info("🛡 USB Monitor Started")
    monitor_usb()
