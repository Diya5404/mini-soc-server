import json
import os
import sys

# Ensure correct path to load correlation module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.correlation import correlate_event

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVENTS_FILE = os.path.join(BASE_DIR, "logs/events.json")

def process_event(event_data):
    # Basic validation
    required_fields = ["event_type", "severity", "source", "message", "timestamp"]
    for field in required_fields:
        if field not in event_data:
            return False, f"Missing field: {field}"
            
    # Save to events.json
    try:
        events = []
        if os.path.exists(EVENTS_FILE):
            with open(EVENTS_FILE, 'r') as f:
                try:
                    events = json.load(f)
                except json.JSONDecodeError:
                    events = []
            
        events.append(event_data)
        
        with open(EVENTS_FILE, 'w') as f:
            json.dump(events, f, indent=4)
            
    except Exception as e:
        print(f"[!] Error saving event: {e}")
        return False, "Error saving event"
        
    # Pass to correlation engine
    correlate_event(event_data)
    
    return True, "Event processed successfully"
