import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template
from engine.ingestion import process_event
from engine.response import get_pending_actions, queue_action
from engine import database

app = Flask(__name__)

# ─── Event Intake ─────────────────────────────────────────────────────────

@app.route('/event', methods=['POST'])
def receive_event():
    event_data = request.json
    if not event_data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    success, msg = process_event(event_data)

    agent_id = event_data.get("source", "unknown")
    actions = get_pending_actions(agent_id)

    if success:
        return jsonify({"status": "success", "message": msg, "actions": actions}), 200
    else:
        return jsonify({"status": "error", "message": msg}), 400

# ─── API Data ─────────────────────────────────────────────────────────────

@app.route('/api/data', methods=['GET'])
def get_data():
    data = {
        "events":    database.get_events(),
        "alerts":    database.get_alerts(),
        "incidents": database.get_incidents(),
        "responses": database.get_responses(),
    }
    return jsonify(data)

# ─── Manual Action Queue ──────────────────────────────────────────────────

@app.route('/api/queue_action', methods=['POST'])
def queue_manual_action():
    data = request.json
    agent_id    = data.get('agent_id')
    action_type = data.get('action_type')
    target      = data.get('target_value')

    if not agent_id or not action_type or not target:
        return jsonify({"error": "Missing required fields"}), 400

    queue_action(agent_id, action_type, target)
    return jsonify({"status": "success", "message": "Action queued"}), 200

# ─── Page Routes ──────────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/events')
def events_page():
    return render_template('events.html')

@app.route('/incidents')
def incidents_page():
    return render_template('incidents.html')

@app.route('/actions')
def actions_page():
    return render_template('actions.html')

# ─── Entry Point ───────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
