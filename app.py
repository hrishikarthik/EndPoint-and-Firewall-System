#app.py
from flask import Flask, render_template, request, jsonify
import requests
import json
import os

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

    logs = logs[::-1]  # Show recent logs first

    # Load existing rules
    rules = []
    if os.path.exists(FIREWALL_RULES_FILE):
        with open(FIREWALL_RULES_FILE, "r") as rf:
            try:
                rules = json.load(rf)
            except json.JSONDecodeError:
                rules = []

    return render_template("firewall.html", logs=logs, rules=rules)

@app.route("/submit_rule", methods=["POST"])
def submit_rule():
    new_rule = {
        "action": request.form.get("action"),
        "protocol": request.form.get("protocol"),
        "src_ip": request.form.get("src_ip"),
        "dst_ip": request.form.get("dst_ip"),
        "port": request.form.get("port")
    }

    # Load existing rules
    rules = []
    if os.path.exists(FIREWALL_RULES_FILE):
        with open(FIREWALL_RULES_FILE, "r") as rf:
            try:
                rules = json.load(rf)
            except json.JSONDecodeError:
                rules = []

    # Append new rule
    rules.append(new_rule)

    # Save back
    with open(FIREWALL_RULES_FILE, "w") as wf:
        json.dump(rules, wf, indent=4)

    return jsonify({"message": "Rule added successfully", "rule": new_rule})


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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
