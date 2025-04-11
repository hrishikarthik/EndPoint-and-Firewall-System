#firewall.py
import json
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# 🔧 Configurable file names (CHANGED: cleaner to define at top)
FIREWALL_RULES_FILE = "firewall_rules.json"
FIREWALL_LOG_FILE = "firewall_log.json"

# ✅ Load all firewall rules
def load_rules():
    try:
        with open(FIREWALL_RULES_FILE, "r") as f:
            return json.load(f)
    except:
        return []  # fallback if file doesn't exist or is broken

# ✅ Compare a packet against a rule (UPDATED: handles src_port & dst_port consistently)
def matches_rule(packet, rule):
    if IP not in packet:
        return False

    ip_layer = packet[IP]
    proto = "TCP" if TCP in packet else "UDP" if UDP in packet else ""

    def match_field(rule_val, pkt_val):
        return rule_val == "" or str(rule_val) == str(pkt_val)  # empty = wildcard

    return (
        match_field(rule.get("src_ip"), ip_layer.src) and
        match_field(rule.get("dst_ip"), ip_layer.dst) and
        match_field(rule.get("protocol"), proto) and
        match_field(rule.get("src_port"), packet.sport if proto else "") and  # 🛠️ FIXED: port extraction
        match_field(rule.get("dst_port"), packet.dport if proto else "")
    )

# 🔍 Callback for each sniffed packet
def packet_callback(packet):
    rules = load_rules()

    for rule in rules:
        if matches_rule(packet, rule):
            if rule.get("action") == "block":
                print(f"🔒 Blocked packet: {packet.summary()}")
                return  # 🚫 Don't log blocked packets
            else:
                break  # ✅ Allowed by rule, continue to log it

    # 📝 Log only allowed packets with IP
    if IP in packet:
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "Other",
            "src_port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else ""),
            "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "")
        }
        # 🗃️ Append to log file
        with open(FIREWALL_LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

# 🚀 Start the packet sniffer
print("🛡️ Firewall monitor with rules started...")
sniff(prn=packet_callback, store=False)
