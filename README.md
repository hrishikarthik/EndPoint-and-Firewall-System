# 🛡️ GuardFusion - EDR + Firewall System

**GuardFusion** is a cloud-deployable cybersecurity solution that combines a custom-built **Firewall** with basic **Endpoint Detection and Response (EDR)** features. Built from scratch using Python and Flask, this lightweight system is designed for real-time monitoring, rule enforcement, and threat response for educational, demo, or internal lab use.

---

## 🚀 Features

### 🔥 Firewall Module
- Add/modify/delete firewall rules via web UI
- Block or allow traffic by IP, Port, and Protocol
- Live logging of traffic attempts

### 🧠 EDR Module
- Monitors suspicious process behavior on endpoints
- Sends logs to a central server (agent-based)
- Basic rule matching for anomaly detection

### 🌐 Web Dashboard
- Real-time log display (traffic + endpoint events)
- Rule management interface (Firewall)
- Alerts for flagged events

---

## 🛠️ Tech Stack

| Component | Tech |
|----------|------|
| Backend  | Python, Flask |
| Frontend | HTML, CSS, JS (vanilla) |
| Logs     | JSON/CSV files or in-memory |
| Deployment | Localhost or free-tier cloud services |

---

## 🧪 Use Cases

- Demonstrating how Firewalls and EDRs work together
- Personal learning or portfolio project
- Lightweight SOC simulator for student labs

---

## 📸 Screenshots

> _Add screenshots here if needed_  
> You can show the dashboard UI, rule form, and live logs.

---

## 🧰 Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/GuardFusion-EDR-Firewall.git
cd GuardFusion-EDR-Firewall
