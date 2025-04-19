import json
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

RULES_FILE = "firewall_rules.json"
LOG_FILE = "firewall_log.json"

def load_rules():
    try:
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    except:
        return []

def matches_rule(packet, rule):
    if IP not in packet:
        return False

    ip_layer = packet[IP]
    proto = "TCP" if TCP in packet else "UDP" if UDP in packet else ""

    def match_field(rule_val, pkt_val):
        return rule_val == "" or str(rule_val) == str(pkt_val)

    src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else "")
    dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "")

    return (
        match_field(rule.get("src_ip"), ip_layer.src) and
        match_field(rule.get("dst_ip"), ip_layer.dst) and
        match_field(rule.get("protocol"), proto) and
        match_field(rule.get("src_port"), src_port) and
        match_field(rule.get("dst_port"), dst_port)
    )

def packet_callback(packet):
    rules = load_rules()
    for rule in rules:
        if matches_rule(packet, rule) and rule.get("action") == "block":
            print(f"🔒 Blocked packet: {packet.summary()}")
            return  # Simulated block (cannot block directly in Scapy on Windows)

    if IP in packet:
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "Other",
            "src_port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else ""),
            "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "")
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

def start_sniffing():
    print("🛡️ Firewall monitor with rules started...")
    sniff(prn=packet_callback, store=False)
