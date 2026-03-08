import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.correlation import correlate_event
from engine import database


def process_event(event_data):
    required_fields = ["event_type", "severity", "source", "message", "timestamp"]
    for field in required_fields:
        if field not in event_data:
            return False, f"Missing field: {field}"

    try:
        database.insert_event(event_data)
    except Exception as e:
        print(f"[!] Error saving event: {e}")
        return False, "Error saving event"

    correlate_event(event_data)
    return True, "Event processed successfully"
