import os
import sys
import json
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.mitre_mapping import map_mitre
from engine.threat_score import calculate_threat_score
from engine.incidents import handle_alert
from engine import database

# In-memory port scan tracker: { ip: {"ports": set(), "timestamp": float} }
connection_tracker = {}
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 60  # seconds


def correlate_event(event_data):
    event_type = event_data.get("event_type")

    if event_type == "suspicious_process":
        generate_alert("suspicious_process", "HIGH", event_data["message"], event_data)

    elif event_type == "system_anomaly":
        generate_alert("system_anomaly", "MEDIUM", event_data["message"], event_data)

    elif event_type == "network_connections":
        try:
            connections = json.loads(event_data["message"])
            detect_port_scan(connections, event_data)
        except (json.JSONDecodeError, TypeError):
            pass


def detect_port_scan(connections, event_data):
    global connection_tracker
    current_time = time.time()

    # Remove stale entries
    for ip in list(connection_tracker.keys()):
        if current_time - connection_tracker[ip]["timestamp"] > PORT_SCAN_WINDOW:
            del connection_tracker[ip]

    for conn in connections:
        peer_ip, peer_port = parse_address(conn.get("peer", ""))
        if not peer_ip or not peer_port:
            continue
        if peer_ip.startswith("127.") or peer_ip in ["::1", "0.0.0.0"] or peer_ip.startswith("fe80:"):
            continue

        if peer_ip not in connection_tracker:
            connection_tracker[peer_ip] = {"ports": set(), "timestamp": current_time}

        connection_tracker[peer_ip]["ports"].add(peer_port)
        connection_tracker[peer_ip]["timestamp"] = current_time

        if len(connection_tracker[peer_ip]["ports"]) > PORT_SCAN_THRESHOLD:
            msg = f"Port scan detected from {peer_ip}. Reached {len(connection_tracker[peer_ip]['ports'])} unique ports."
            generate_alert("port_scan_detected", "HIGH", msg, event_data)

            agent_id = event_data.get("source", "user_vm")
            database.queue_action(agent_id, "iptables_block", peer_ip)

            connection_tracker[peer_ip]["ports"].clear()


def parse_address(address_str):
    if not address_str:
        return None, None
    parts = address_str.rsplit(":", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return None, None


def generate_alert(alert_type, base_severity, message, original_event):
    mitre_info = map_mitre(alert_type)
    threat_score = calculate_threat_score(base_severity)

    alert = {
        "alert_type": alert_type,
        "severity": base_severity,
        "message": message,
        "timestamp": original_event.get("timestamp"),
        "source": original_event.get("source"),
        "threat_score": threat_score,
        "mitre_technique": mitre_info.get("technique"),
        "mitre_name": mitre_info.get("name"),
    }

    try:
        database.insert_alert(alert)
    except Exception as e:
        print(f"[!] Error saving alert: {e}")

    handle_alert(alert)
