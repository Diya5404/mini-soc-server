import json
import os
import time
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.mitre_mapping import map_mitre
from engine.threat_score import calculate_threat_score
from engine.incidents import handle_alert

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS_FILE = os.path.join(BASE_DIR, "logs/alerts.json")

# In-memory store for port scan detection
# Track connection attempts: { "ip": { "ports": set(), "timestamp": time } }
connection_tracker = {}
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 60 # seconds

def correlate_event(event_data):
    event_type = event_data.get("event_type")
    
    if event_type == "suspicious_process":
        # Rule: suspicious_process -> HIGH alert
        generate_alert("suspicious_process", "HIGH", event_data["message"], event_data)
        
    elif event_type == "system_anomaly":
        # Rule: CPU spike anomaly -> MEDIUM alert
        generate_alert("system_anomaly", "MEDIUM", event_data["message"], event_data)
        
    elif event_type == "network_connections":
        # Rule: repeated connections to many ports from same IP -> port_scan_detected
        try:
            connections = json.loads(event_data["message"])
            detect_port_scan(connections, event_data)
        except json.JSONDecodeError:
            pass

def detect_port_scan(connections, event_data):
    global connection_tracker
    current_time = time.time()
    
    # Cleanup old entries
    for ip in list(connection_tracker.keys()):
        if current_time - connection_tracker[ip]["timestamp"] > PORT_SCAN_WINDOW:
            del connection_tracker[ip]

    for conn in connections:
        peer_ip, peer_port = parse_address(conn.get("peer", ""))
        if not peer_ip or not peer_port:
            continue
            
        # Ignore localhost/loopback addresses to prevent false positives from local services
        if peer_ip.startswith("127.") or peer_ip in ["::1", "0.0.0.0"] or peer_ip.startswith("fe80:"):
            continue
            
        if peer_ip not in connection_tracker:
            connection_tracker[peer_ip] = {"ports": set(), "timestamp": current_time}
            
        connection_tracker[peer_ip]["ports"].add(peer_port)
        connection_tracker[peer_ip]["timestamp"] = current_time
        
        if len(connection_tracker[peer_ip]["ports"]) > PORT_SCAN_THRESHOLD:
            # Generate alert
            msg = f"Port scan detected from {peer_ip}. Reached {len(connection_tracker[peer_ip]['ports'])} unique ports."
            generate_alert("port_scan_detected", "HIGH", msg, event_data)
            # Reset tracker to avoid spamming
            connection_tracker[peer_ip]["ports"].clear()

def parse_address(address_str):
    # address_str format: IP:PORT e.g. 10.0.2.2:53456 or [::1]:22
    if not address_str:
        return None, None
    parts = address_str.rsplit(':', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return None, None

def generate_alert(alert_type, base_severity, message, original_event):
    # Apply MITRE mapping
    mitre_info = map_mitre(alert_type)
    
    # Calculate threat score
    threat_score = calculate_threat_score(base_severity)
    
    alert = {
        "alert_type": alert_type,
        "severity": base_severity,
        "message": message,
        "timestamp": original_event.get("timestamp"),
        "source": original_event.get("source"),
        "threat_score": threat_score,
        "mitre_technique": mitre_info.get("technique"),
        "mitre_name": mitre_info.get("name")
    }
    
    # Save to alerts.json
    try:
        alerts = []
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, 'r') as f:
                try:
                    alerts = json.load(f)
                except json.JSONDecodeError:
                    alerts = []
            
        alerts.append(alert)
        with open(ALERTS_FILE, 'w') as f:
            json.dump(alerts, f, indent=4)
            
    except Exception as e:
        print(f"[!] Error saving alert: {e}")
        
    # Pass to incident manager
    handle_alert(alert)
