"""
Advanced correlation engine with multi-rule detection.
Detects: port scans, brute force, lateral movement, connection rate spikes,
         SYN floods, DDoS combo, suspicious processes, DNS anomalies, CPU spikes.
"""

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

# ─── In-memory state (cleared on restart, fine for SOC lab) ──────────────

# Port scan tracker  { ip: {"ports": set(), "ts": float} }
_port_tracker = {}

# Brute force tracker { ip: { port: [timestamps] } }
_brute_tracker = collections.defaultdict(lambda: collections.defaultdict(list))

# Lateral movement tracker { source_ip: { dest_ip: set(ports) } }
_lateral_tracker = collections.defaultdict(lambda: collections.defaultdict(set))

# Connection rate tracker  [recent total connection counts with timestamps]
_conn_rate_history = collections.deque(maxlen=30)  # last 30 samples

# SYN flood tracker { ip: [timestamps] }
_syn_tracker = collections.defaultdict(list)

# DNS query tracker { ip: [timestamps] }
_dns_tracker = collections.defaultdict(list)

# Thresholds
PORT_SCAN_THRESHOLD       = 15   # unique ports within window
PORT_SCAN_WINDOW          = 60   # seconds
BRUTE_FORCE_THRESHOLD     = 8    # connections to same port within window
BRUTE_FORCE_WINDOW        = 30   # seconds
BRUTE_FORCE_PORTS         = {"22", "23", "21", "3389", "5900", "445", "3306", "1433"}
LATERAL_IP_THRESHOLD      = 4    # ≥4 internal IPs touched
LATERAL_PORT_THRESHOLD    = 3    # ≥3 different ports per destination
CONN_RATE_SPIKE_FACTOR    = 3.0  # current > 3× recent average
CONN_RATE_MIN_SAMPLES     = 5    # need at least 5 samples before alerting
SYN_FLOOD_THRESHOLD       = 30   # SYN_SENT connections from same IP in window
SYN_FLOOD_WINDOW          = 30   # seconds
DNS_FLOOD_THRESHOLD       = 50   # DNS queries from same IP in window
DNS_FLOOD_WINDOW          = 60   # seconds
INTERNAL_PREFIXES         = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                             "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                             "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                             "172.29.", "172.30.", "172.31.")


# ─── Entry point ─────────────────────────────────────────────────────────

def correlate_event(event_data):
    event_type = event_data.get("event_type")

    if event_type == "suspicious_process":
        _rule_suspicious_process(event_data)

    elif event_type == "system_anomaly":
        _rule_cpu_anomaly(event_data)

    elif event_type == "network_connections":
        try:
            connections = json.loads(event_data["message"])
            _rule_port_scan(connections, event_data)
            _rule_brute_force(connections, event_data)
            _rule_lateral_movement(connections, event_data)
            _rule_connection_rate_spike(connections, event_data)
            _rule_syn_flood(connections, event_data)
            _rule_dns_flood(connections, event_data)
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


# ─── Rule 3: Port Scan (T1046) ───────────────────────────────────────────

def _rule_port_scan(connections, event_data):
    now = time.time()

    # Clean stale
    for ip in list(_port_tracker.keys()):
        if now - _port_tracker[ip]["ts"] > PORT_SCAN_WINDOW:
            del _port_tracker[ip]

    for conn in connections:
        peer_ip, peer_port = _split_addr(conn.get("peer", ""))
        if not peer_ip or not peer_port or _is_loopback(peer_ip):
            continue

        if peer_ip not in _port_tracker:
            _port_tracker[peer_ip] = {"ports": set(), "ts": now}

        _port_tracker[peer_ip]["ports"].add(peer_port)
        _port_tracker[peer_ip]["ts"] = now

        unique = len(_port_tracker[peer_ip]["ports"])
        if unique >= PORT_SCAN_THRESHOLD:
            msg = (f"Port scan detected from {peer_ip} — "
                   f"{unique} unique ports probed within {PORT_SCAN_WINDOW}s")
            generate_alert("port_scan_detected", "HIGH", msg, event_data)
            agent_id = event_data.get("source", "user_vm")
            database.queue_action(agent_id, "iptables_block", peer_ip)
            _port_tracker[peer_ip]["ports"].clear()


# ─── Rule 4: Brute Force (T1110) ─────────────────────────────────────────

def _rule_brute_force(connections, event_data):
    now = time.time()

    for conn in connections:
        peer_ip, peer_port = _split_addr(conn.get("peer", ""))
        local_ip, local_port = _split_addr(conn.get("local", ""))
        if not peer_ip or not local_port or _is_loopback(peer_ip):
            continue

        if local_port in BRUTE_FORCE_PORTS:
            _brute_tracker[peer_ip][local_port].append(now)
            # Prune old
            _brute_tracker[peer_ip][local_port] = [
                t for t in _brute_tracker[peer_ip][local_port]
                if now - t <= BRUTE_FORCE_WINDOW
            ]
            count = len(_brute_tracker[peer_ip][local_port])
            if count >= BRUTE_FORCE_THRESHOLD:
                msg = (f"Brute force attempt detected from {peer_ip} on port {local_port} — "
                       f"{count} connections in {BRUTE_FORCE_WINDOW}s")
                generate_alert("brute_force_detected", "HIGH", msg, event_data)
                agent_id = event_data.get("source", "user_vm")
                database.queue_action(agent_id, "iptables_block", peer_ip)
                _brute_tracker[peer_ip][local_port].clear()


# ─── Rule 5: Lateral Movement (T1021) ────────────────────────────────────

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


# ─── Rule 6: Connection Rate Spike (T1499 / T1595) ───────────────────────

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


# ─── Rule 7: SYN Flood (T1498) ───────────────────────────────────────────

def _rule_syn_flood(connections, event_data):
    now = time.time()
    syn_counts = collections.Counter()

    for conn in connections:
        if conn.get("state", "").upper() in ("SYN-SENT", "SYN_SENT"):
            peer_ip, _ = _split_addr(conn.get("peer", ""))
            if peer_ip and not _is_loopback(peer_ip):
                _syn_tracker[peer_ip].append(now)
                _syn_tracker[peer_ip] = [
                    t for t in _syn_tracker[peer_ip] if now - t <= SYN_FLOOD_WINDOW
                ]
                count = len(_syn_tracker[peer_ip])
                if count >= SYN_FLOOD_THRESHOLD:
                    msg = (f"SYN flood detected from {peer_ip} — "
                           f"{count} SYN connections in {SYN_FLOOD_WINDOW}s")
                    generate_alert("syn_flood_detected", "HIGH", msg, event_data)
                    agent_id = event_data.get("source", "user_vm")
                    database.queue_action(agent_id, "iptables_block", peer_ip)
                    _syn_tracker[peer_ip].clear()


# ─── Rule 8: DNS Flood / Tunneling (T1071.004) ───────────────────────────

def _rule_dns_flood(connections, event_data):
    now = time.time()

    for conn in connections:
        peer_ip, peer_port = _split_addr(conn.get("peer", ""))
        if peer_port == "53" and peer_ip and not _is_loopback(peer_ip):
            _dns_tracker[peer_ip].append(now)
            _dns_tracker[peer_ip] = [
                t for t in _dns_tracker[peer_ip] if now - t <= DNS_FLOOD_WINDOW
            ]
            count = len(_dns_tracker[peer_ip])
            if count >= DNS_FLOOD_THRESHOLD:
                msg = (f"DNS flood / tunneling suspected from {peer_ip} — "
                       f"{count} DNS queries in {DNS_FLOOD_WINDOW}s")
                generate_alert("dns_anomaly_detected", "MEDIUM", msg, event_data)
                _dns_tracker[peer_ip].clear()


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
