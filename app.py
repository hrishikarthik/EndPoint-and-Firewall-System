from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import json
import os
import threading
from firewall import start_sniffing

app = Flask(__name__)
EDR_API_URL = "http://127.0.0.1:5001"

FIREWALL_LOG_FILE = "firewall_log.json"
FIREWALL_RULES_FILE = "firewall_rules.json"

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/edr")
def edr_dashboard():
    return render_template("edr.html")

@app.route("/firewall")
def firewall_page():
    logs = []
    try:
        with open(FIREWALL_LOG_FILE, "r") as f:
            for line in f:
                try:
                    logs.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        logs = []

    logs = logs[::-1]

    rules = []
    if os.path.exists(FIREWALL_RULES_FILE):
        with open(FIREWALL_RULES_FILE, "r") as rf:
            try:
                rules = json.load(rf)
            except json.JSONDecodeError:
                rules = []

    return render_template("firewall.html", logs=logs, rules=rules)

@app.route("/add_rule", methods=["POST"])
def add_rule():
    new_rule = {
        "action": request.form.get("action", ""),
        "protocol": request.form.get("protocol", ""),
        "src_ip": request.form.get("src_ip", ""),
        "dst_ip": request.form.get("dst_ip", ""),
        "src_port": request.form.get("src_port", ""),
        "dst_port": request.form.get("dst_port", "")
    }

    rules = []
    if os.path.exists(FIREWALL_RULES_FILE):
        with open(FIREWALL_RULES_FILE, "r") as rf:
            try:
                rules = json.load(rf)
            except json.JSONDecodeError:
                rules = []

    rules.append(new_rule)

    with open(FIREWALL_RULES_FILE, "w") as wf:
        json.dump(rules, wf, indent=4)

    return redirect(url_for('firewall_page'))

@app.route("/get_processes")
def get_processes():
    try:
        response = requests.get(f"{EDR_API_URL}/processes")
        return jsonify(response.json())
    except:
        return jsonify([])

@app.route("/kill/<int:pid>")
def kill_process(pid):
    try:
        response = requests.post(f"{EDR_API_URL}/kill/{pid}")
        return jsonify(response.json())
    except:
        return jsonify({"message": "Failed to reach EDR API"})

def run_packet_sniffing():
    start_sniffing()

if __name__ == "__main__":
    threading.Thread(target=run_packet_sniffing, daemon=True).start()
    app.run(debug=True)
