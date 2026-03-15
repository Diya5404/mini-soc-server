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

    try:
        if event_data.get("event_type") == "response_executed":
            # Message format: "iptables_block 10.0.3.5: success [details]"
            msg = event_data.get("message", "")
            action_type = "unknown"
            target = "unknown"
            status = "unknown"
            details = ""
            
            parts = msg.split(":", 1)
            if len(parts) == 2:
                left_side = parts[0].strip().split()
                if len(left_side) >= 2:
                    action_type = left_side[0]
                    target = left_side[1]
                
                right_side = parts[1].strip().split(" ", 1)
                status = right_side[0]
                if len(right_side) > 1:
                    details = right_side[1]
                    
            from engine.response import log_response
            log_response(event_data["source"], action_type, target, status, details)
        else:
            correlate_event(event_data)
    except Exception as e:
        print(f"[!] Processing error: {e}")
        # We still return True because the event IS saved, only detection/logging failed
        
    return True, "Event processed successfully"
