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

def is_filtered(source_ip, peer_ip, peer_port, state):
    """Filter out normal/noise traffic."""
    # Ignore localhost
    if source_ip == "127.0.0.1" or peer_ip == "127.0.0.1":
        return True
    
    # Ignore established/long-lived connections for scan detection
    if state == "ESTABLISHED":
        return True
        
    # Prevent Self-Blocking: Ignore OUTBOUND connections (where the agent is sending).
    # If the victim VM initiated the connection, the peer_port is usually a well-known
    # service port (80, 443, etc.) and our local_port is a random high ephemeral port.
    if peer_port in ("80", "443", "5000", "5432", "6379"):
        return True
        
    # Ignore explicit outbound connection attempts
    if state == "SYN_SENT":
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
    """Detect port scanning behavior (HIGH severity)."""
    relevant_conns = [
        conn for conn in connection_history[source_ip]
        if current_time - conn[1] <= PORT_SCAN_WINDOW
    ]
    unique_ports = {conn[0] for conn in relevant_conns}
    count = len(unique_ports)
    
    # User requested port scans be HIGH severity. 
    # Trigger at 5+ ports to catch early scans.
    if count >= 5:
        alert_type = "port_scan_detected"
        if check_cooldown(source_ip, alert_type, current_time):
            last_alert_time[(source_ip, alert_type)] = current_time
            return True, "HIGH", f"HIGH SEVERITY: Port scan detected from {source_ip} ({count} unique ports)"
            
    return False, None, ""

def detect_ssh_brute_force(source_ip, current_time):
    """Detect SSH brute force attempts (HIGH severity)."""
    ssh_conns = [
        conn for conn in connection_history[source_ip]
        if conn[0] == "22" and current_time - conn[1] <= SSH_BRUTE_FORCE_WINDOW
    ]
    count = len(ssh_conns)
    
    # User requested brute force be HIGH severity.
    # Trigger at 5+ attempts.
    if count >= 5:
        alert_type = "ssh_bruteforce_detected"
        if check_cooldown(source_ip, alert_type, current_time):
            last_alert_time[(source_ip, alert_type)] = current_time
            return True, "HIGH", f"HIGH SEVERITY: SSH brute force attempts from {source_ip} ({count} attempts)"
            
    return False, None, ""

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

        if is_filtered(source_ip, peer_ip, peer_port, state):
            continue
            
        # Add to history: Track which port on the victim was contacted by the peer
        # connection_history[peer_ip] = [(local_port, timestamp), ...]
        connection_history[peer_ip].append((local_port, current_time))
        affected_ips.add(peer_ip)
        
    # Perform cleanup and rule checks once per affected IP
    for peer_ip in affected_ips:
        cleanup_old_entries(peer_ip, current_time)
        
        # Port Scan Check
        is_scan, severity, scan_msg = detect_port_scan(peer_ip, current_time)
        if is_scan:
            alerts.append({
                "type": "port_scan_detected",
                "severity": severity,
                "message": scan_msg,
                "attacker_ip": peer_ip
            })
            
        # SSH Brute Force Check
        is_bf, severity, bf_msg = detect_ssh_brute_force(peer_ip, current_time)
        if is_bf:
            alerts.append({
                "type": "ssh_bruteforce_detected",
                "severity": severity,
                "message": bf_msg,
                "attacker_ip": peer_ip
            })
            
    return alerts
