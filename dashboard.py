from flask import Flask, render_template, jsonify, request
import requests

app = Flask(__name__)
EDR_API_URL = "http://127.0.0.1:5001"  # EDR backend API

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/edr")
def edr_dashboard():
    return render_template("edr.html")

@app.route("/firewall")
def firewall_dashboard():
    return render_template("firewall.html")  # Placeholder

@app.route("/get_processes")
def get_processes():
    try:
        response = requests.get(f"{EDR_API_URL}/processes")
        return jsonify(response.json())
    except requests.exceptions.RequestException:
        return jsonify([])

@app.route("/kill/<int:pid>")
def kill_process(pid):
    try:
        response = requests.post(f"{EDR_API_URL}/kill/{pid}")
        return jsonify(response.json())
    except requests.exceptions.RequestException:
        return jsonify({"message": "EDR API not reachable"})

if __name__ == "__main__":
    app.run(debug=True)
