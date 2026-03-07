import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INCIDENTS_FILE = os.path.join(BASE_DIR, "logs/incidents.json")

def handle_alert(alert):
    # Confirmed alerts are stored as incidents
    # For now, we consider all generated alerts as confirmed incidents
    
    incident = {
        "severity": alert.get("severity"),
        "message": alert.get("message"),
        "timestamp": alert.get("timestamp"),
        "threat_score": alert.get("threat_score"),
        "mitre_technique": alert.get("mitre_technique")
    }
    
    try:
        incidents = []
        if os.path.exists(INCIDENTS_FILE):
            with open(INCIDENTS_FILE, 'r') as f:
                try:
                    incidents = json.load(f)
                except json.JSONDecodeError:
                    incidents = []
            
        incidents.append(incident)
        with open(INCIDENTS_FILE, 'w') as f:
            json.dump(incidents, f, indent=4)
            
    except Exception as e:
        print(f"[!] Error saving incident: {e}")
