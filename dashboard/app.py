import sys
import os

# Add the project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template
import json
from engine.ingestion import process_event

app = Flask(__name__)

# Base path for logs
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "logs")

@app.route('/event', methods=['POST'])
def receive_event():
    event_data = request.json
    if not event_data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400
        
    success, msg = process_event(event_data)
    if success:
        return jsonify({"status": "success", "message": msg}), 200
    else:
        return jsonify({"status": "error", "message": msg}), 400

@app.route('/api/data', methods=['GET'])
def get_data():
    data = {
        "events": [],
        "alerts": [],
        "incidents": []
    }
    
    try:
        events_file = os.path.join(LOGS_DIR, "events.json")
        if os.path.exists(events_file):
            with open(events_file, 'r') as f:
                try:
                    data["events"] = json.load(f)
                except json.JSONDecodeError:
                    pass
                
        alerts_file = os.path.join(LOGS_DIR, "alerts.json")
        if os.path.exists(alerts_file):
            with open(alerts_file, 'r') as f:
                try:
                    data["alerts"] = json.load(f)
                except json.JSONDecodeError:
                    pass
                
        incidents_file = os.path.join(LOGS_DIR, "incidents.json")
        if os.path.exists(incidents_file):
            with open(incidents_file, 'r') as f:
                try:
                    data["incidents"] = json.load(f)
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        print(f"Error reading logs: {e}")
        
    return jsonify(data)

@app.route('/')
def dashboard():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
