import os
import sys
import json
import time
import collections

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.mitre_mapping import map_mitre
from engine.threat_score import calculate_threat_score
from engine.incidents import handle_alert
from engine import database
from engine.detection_engine import analyze_connections

# ─── In-memory state ──────────────────────────────────────────────────────

# Lateral movement tracker { source_ip: { dest_ip: set(ports) } }
_lateral_tracker = collections.defaultdict(lambda: collections.defaultdict(set))

# Connection rate tracker  [recent total connection counts with timestamps]
_conn_rate_history = collections.deque(maxlen=30)  # last 30 samples

# Thresholds
LATERAL_IP_THRESHOLD      = 3    # ≥3 internal IPs touched
LATERAL_PORT_THRESHOLD    = 2    # ≥2 different ports per destination
CONN_RATE_SPIKE_FACTOR    = 2.5  # current > 2.5× recent average
CONN_RATE_MIN_SAMPLES     = 4    # need at least 4 samples before alerting

INTERNAL_PREFIXES         = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                             "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                             "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                             "172.29.", "172.30.", "172.31.")


# ─── Entry point ─────────────────────────────────────────────────────────

def correlate_event(event_data):
    event_type = event_data.get("event_type")
    source_ip = event_data.get("source", "unknown")

    if event_type == "suspicious_process":
        _rule_suspicious_process(event_data)

    elif event_type == "system_anomaly":
        _rule_cpu_anomaly(event_data)

    elif event_type == "network_connections":
        try:
            connections = json.loads(event_data["message"])
            
            # --- Behavioral Detection Engine ---
            behavioral_alerts = analyze_connections(source_ip, connections)
            for alert in behavioral_alerts:
                severity = alert["severity"]
                generate_alert(
                    alert["type"], 
                    severity, 
                    alert["message"], 
                    event_data
                )
                
                # Active Response only for severe threats
                if severity in ("HIGH", "CRITICAL") and "attacker_ip" in alert:
                    database.queue_action(source_ip, "iptables_block", alert["attacker_ip"])

            # --- Other Rules (Lateral, Spike) ---
            _rule_lateral_movement(connections, event_data)
            _rule_connection_rate_spike(connections, event_data)
            
        except (json.JSONDecodeError, TypeError):
            pass


# ─── Rule 1: Suspicious Process (T1204 / T1059) ──────────────────────────

def _rule_suspicious_process(event_data):
    generate_alert("suspicious_process", "HIGH", event_data["message"], event_data)


# ─── Rule 2: CPU Anomaly / Resource Exhaustion (T1499) ──────────────────

def _rule_cpu_anomaly(event_data):
    msg = event_data.get("message", "")
    if "spike" in msg.lower() or "high" in msg.lower():
        generate_alert("system_anomaly", "HIGH", msg, event_data)
    else:
        generate_alert("system_anomaly", "MEDIUM", msg, event_data)


# ─── Rule 3: Lateral Movement (T1021) ────────────────────────────────────

def _rule_lateral_movement(connections, event_data):
    now = time.time()
    source = event_data.get("source", "user_vm")

    for conn in connections:
        peer_ip, peer_port = _split_addr(conn.get("peer", ""))
        if not peer_ip or not peer_port or _is_loopback(peer_ip):
            continue
        if not _is_internal(peer_ip):
            continue

        _lateral_tracker[source][peer_ip].add(peer_port)

    internal_ips = list(_lateral_tracker[source].keys())
    if len(internal_ips) >= LATERAL_IP_THRESHOLD:
        targets = [f"{ip}:{len(ports)} ports" for ip, ports in _lateral_tracker[source].items()]
        msg = (f"Lateral movement detected from agent {source} — "
               f"contacted {len(internal_ips)} internal IPs: {', '.join(targets[:5])}")
        generate_alert("lateral_movement_detected", "HIGH", msg, event_data)
        _lateral_tracker[source].clear()


# ─── Rule 4: Connection Rate Spike (T1499 / T1595) ───────────────────────

def _rule_connection_rate_spike(connections, event_data):
    now = time.time()
    count = len(connections)
    _conn_rate_history.append((now, count))

    if len(_conn_rate_history) < CONN_RATE_MIN_SAMPLES:
        return

    counts = [c for _, c in _conn_rate_history]
    avg = sum(counts[:-1]) / len(counts[:-1])  # exclude current sample
    current = counts[-1]

    if avg > 0 and current > avg * CONN_RATE_SPIKE_FACTOR:
        msg = (f"Connection rate spike — current: {current} connections, "
               f"avg: {avg:.1f} ({CONN_RATE_SPIKE_FACTOR}× threshold exceeded)")
        generate_alert("connection_rate_spike", "MEDIUM", msg, event_data)


# ─── Alert Generator ─────────────────────────────────────────────────────

def generate_alert(alert_type, base_severity, message, original_event):
    mitre_info  = map_mitre(alert_type)
    threat_score = calculate_threat_score(base_severity)

    alert = {
        "alert_type":      alert_type,
        "severity":        base_severity,
        "message":         message,
        "timestamp":       original_event.get("timestamp"),
        "source":          original_event.get("source"),
        "threat_score":    threat_score,
        "mitre_technique": mitre_info.get("technique"),
        "mitre_name":      mitre_info.get("name"),
    }

    try:
        database.insert_alert(alert)
    except Exception as e:
        print(f"[!] Error saving alert: {e}")

    handle_alert(alert)


# ─── Utilities ────────────────────────────────────────────────────────────

def _split_addr(address_str):
    """Split 'IP:PORT' → (ip, port). Handles IPv6 bracketed addresses."""
    if not address_str:
        return None, None
    parts = address_str.rsplit(":", 1)
    if len(parts) == 2:
        return parts[0].strip("[]"), parts[1]
    return None, None


def _is_loopback(ip):
    return ip.startswith("127.") or ip in ("::1", "0.0.0.0") or ip.startswith("fe80:")


def _is_internal(ip):
    return any(ip.startswith(p) for p in INTERNAL_PREFIXES)
