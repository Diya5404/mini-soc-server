import time
from collections import defaultdict

# Configuration
PORT_SCAN_WINDOW = 30  # seconds (was 10)
PORT_SCAN_THRESHOLD = 10  # unique ports (was 20)
SSH_BRUTE_FORCE_WINDOW = 15  # seconds
SSH_BRUTE_FORCE_THRESHOLD = 10  # attempts
ALERT_COOLDOWN = 30  # seconds

# State Tracking
# connection_history[source_ip] = [(port, timestamp), ...]
connection_history = defaultdict(list)
# last_alert_time[(source_ip, alert_type)] = timestamp
last_alert_time = {}

def is_filtered(source_ip, peer_ip, state):
    """Filter out normal/noise traffic."""
    # Ignore localhost
    if source_ip == "127.0.0.1" or peer_ip == "127.0.0.1":
        return True
    # Ignore established/long-lived connections for scan detection
    # (Focus on new/attempted connections like SYN_SENT/SYN_RECV)
    if state == "ESTABLISHED":
        return True
    return False

def cleanup_old_entries(source_ip, current_time):
    """Remove entries older than the longest tracking window."""
    max_window = max(PORT_SCAN_WINDOW, SSH_BRUTE_FORCE_WINDOW)
    connection_history[source_ip] = [
        conn for conn in connection_history[source_ip]
        if current_time - conn[1] <= max_window
    ]

def check_cooldown(source_ip, alert_type, current_time):
    """Check if an alert of this type for this IP is in cooldown."""
    key = (source_ip, alert_type)
    if key in last_alert_time:
        if current_time - last_alert_time[key] < ALERT_COOLDOWN:
            return False
    return True

def detect_port_scan(source_ip, current_time):
    """Detect port scanning behavior (unique ports in window)."""
    relevant_conns = [
        conn for conn in connection_history[source_ip]
        if current_time - conn[1] <= PORT_SCAN_WINDOW
    ]
    unique_ports = {conn[0] for conn in relevant_conns}
    
    if len(unique_ports) > PORT_SCAN_THRESHOLD:
        if check_cooldown(source_ip, "port_scan_detected", current_time):
            last_alert_time[(source_ip, "port_scan_detected")] = current_time
            return True, f"Possible Nmap scan from {source_ip} contacting {len(unique_ports)} unique ports"
    return False, ""

def detect_ssh_brute_force(source_ip, current_time):
    """Detect SSH brute force attempts (frequency on port 22)."""
    ssh_conns = [
        conn for conn in connection_history[source_ip]
        if conn[0] == "22" and current_time - conn[1] <= SSH_BRUTE_FORCE_WINDOW
    ]
    
    if len(ssh_conns) > SSH_BRUTE_FORCE_THRESHOLD:
        if check_cooldown(source_ip, "ssh_bruteforce_detected", current_time):
            last_alert_time[(source_ip, "ssh_bruteforce_detected")] = current_time
            return True, f"Multiple SSH login attempts detected from {source_ip} ({len(ssh_conns)} attempts)"
    return False, ""

def analyze_connections(source_ip, connections, current_time=None):
    """Main entry point for analyzing a batch of connections from an agent."""
    if current_time is None:
        current_time = time.time()
        
    alerts = []
    affected_ips = set()
    
    for conn in connections:
        peer_addr = conn.get("peer", "") # Attacker (Source)
        local_addr = conn.get("local", "") # Victim (Destination)
        state = conn.get("state", "").upper()
        
        # Parse IPs and Ports
        try:
            if ":" in peer_addr and ":" in local_addr:
                peer_ip, peer_port = peer_addr.rsplit(":", 1)
                local_ip, local_port = local_addr.rsplit(":", 1)
            else:
                continue # Skip invalid
        except ValueError:
            continue

        if is_filtered(source_ip, peer_ip, state):
            continue
            
        # Add to history: Track which port on the victim was contacted by the peer
        # connection_history[peer_ip] = [(local_port, timestamp), ...]
        connection_history[peer_ip].append((local_port, current_time))
        affected_ips.add(peer_ip)
        
    # Perform cleanup and rule checks once per affected IP
    for peer_ip in affected_ips:
        cleanup_old_entries(peer_ip, current_time)
        
        # Port Scan Check
        is_scan, scan_msg = detect_port_scan(peer_ip, current_time)
        if is_scan:
            alerts.append({
                "type": "port_scan_detected",
                "severity": "HIGH",
                "message": scan_msg,
                "attacker_ip": peer_ip
            })
            
        # SSH Brute Force Check
        is_bf, bf_msg = detect_ssh_brute_force(peer_ip, current_time)
        if is_bf:
            alerts.append({
                "type": "ssh_bruteforce_detected",
                "severity": "HIGH",
                "message": bf_msg,
                "attacker_ip": peer_ip
            })
            
    return alerts
