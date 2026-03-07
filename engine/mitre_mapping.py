def map_mitre(alert_type):
    mapping = {
        "port_scan_detected": {
            "technique": "T1046",
            "name": "Network Service Scanning"
        },
        "suspicious_process": {
            "technique": "T1046",
            "name": "Network Service Scanning"
        },
        "system_anomaly": {
            "technique": "T1499",
            "name": "Resource Exhaustion"
        }
    }
    
    return mapping.get(alert_type, {"technique": "Unknown", "name": "Unknown"})
