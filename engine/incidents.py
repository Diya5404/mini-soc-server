import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import database


def handle_alert(alert):
    incident = {
        "severity": alert.get("severity"),
        "message": alert.get("message"),
        "timestamp": alert.get("timestamp"),
        "threat_score": alert.get("threat_score"),
        "mitre_technique": alert.get("mitre_technique"),
    }
    try:
        database.insert_incident(incident)
    except Exception as e:
        print(f"[!] Error saving incident: {e}")
