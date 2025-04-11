import os
import psutil
import hashlib
import shutil
import logging
from datetime import datetime

from flask import Flask, jsonify
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

logging.basicConfig(filename="edr_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

QUARANTINE_FOLDER = "quarantine"
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

MALICIOUS_PROCESSES = ["malware.exe", "virus.exe", "trojan.exe", "ransomware.exe"]
MALICIOUS_HASHES = {"5d41402abc4b2a76b9719d911017c592"}

def get_file_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except FileNotFoundError:
        return None

def quarantine_process(pid, filepath):
    try:
        filename = os.path.basename(filepath)
        shutil.move(filepath, os.path.join(QUARANTINE_FOLDER, filename))
        logging.info(f"🔒 Quarantined: {filename} (PID: {pid})")
    except Exception as e:
        logging.error(f"Failed to quarantine {filepath}: {e}")

def detect_malicious_processes():
    for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
        try:
            pid, name, exe = proc.info["pid"], proc.info["name"], proc.info["exe"]

            if name.lower() in MALICIOUS_PROCESSES:
                proc.terminate()
                logging.info(f"❌ Killed: {name} (PID: {pid})")
                continue

            if exe:
                file_hash = get_file_hash(exe)
                if file_hash in MALICIOUS_HASHES:
                    proc.terminate()
                    quarantine_process(pid, exe)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def get_all_processes():
    processes = []
    for p in psutil.process_iter(attrs=["pid", "name", "exe", "create_time"]):
        try:
            readable_time = datetime.fromtimestamp(p.info["create_time"]).strftime("%Y-%m-%d %H:%M:%S")
            processes.append({
                "pid": p.info["pid"],
                "name": p.info["name"],
                "path": p.info.get("exe", "N/A"),
                "start_time": readable_time
            })
        except Exception:
            continue
    processes.sort(key=lambda x: x["start_time"], reverse=True)
    return processes

@app.route("/processes", methods=["GET"])
def list_processes():
    detect_malicious_processes()
    return jsonify(get_all_processes())

@app.route("/kill/<int:pid>", methods=["POST"])
def kill_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        logging.info(f"❌ Manually killed: {proc.name()} (PID: {pid})")
        return jsonify({"message": f"Process {proc.name()} (PID: {pid}) terminated."})
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return jsonify({"message": f"⚠️ Failed to terminate PID: {pid}"}), 400

# Emit data periodically
import threading, time
def background_process():
    while True:
        detect_malicious_processes()
        socketio.emit("process_update", get_all_processes())
        time.sleep(2)  # update every 2s

threading.Thread(target=background_process, daemon=True).start()

if __name__ == "__main__":
    socketio.run(app, port=5001)
