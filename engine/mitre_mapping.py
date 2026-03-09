MITRE_MAP = {
    # Process-based
    "suspicious_process": {
        "technique": "T1059",
        "name": "Command and Scripting Interpreter"
    },
    # Network scanning
    "port_scan_detected": {
        "technique": "T1046",
        "name": "Network Service Scanning"
    },
    # Brute force / credential access
    "brute_force_detected": {
        "technique": "T1110",
        "name": "Brute Force"
    },
    "ssh_bruteforce_detected": {
        "technique": "T1110",
        "name": "Brute Force"
    },
    # Lateral movement
    "lateral_movement_detected": {
        "technique": "T1021",
        "name": "Remote Services"
    },
    # Connection rate / active scanning
    "connection_rate_spike": {
        "technique": "T1595",
        "name": "Active Scanning"
    },
    # SYN flood / DoS
    "syn_flood_detected": {
        "technique": "T1498",
        "name": "Network Denial of Service"
    },
    # DNS tunneling / C2
    "dns_anomaly_detected": {
        "technique": "T1071.004",
        "name": "Application Layer Protocol: DNS"
    },
    # CPU / resource exhaustion
    "system_anomaly": {
        "technique": "T1499",
        "name": "Endpoint Denial of Service"
    },
    # Agent-executed responses
    "prevention_action": {
        "technique": "N/A",
        "name": "Automated Prevention"
    },
    "response_executed": {
        "technique": "N/A",
        "name": "Automated Response"
    },
}


def map_mitre(alert_type):
    return MITRE_MAP.get(alert_type, {"technique": "T0000", "name": "Unknown Technique"})
