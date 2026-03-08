import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import database


def queue_action(agent_id, action_type, target):
    """Queue a response action for an agent to execute on its next check-in."""
    database.queue_action(agent_id, action_type, target)


def get_pending_actions(agent_id):
    """Retrieve and clear pending actions for an agent."""
    return database.get_pending_actions(agent_id)


def log_response(agent_id, action_type, target, status, details):
    """Log an executed response action for the dashboard."""
    database.log_response(agent_id, action_type, target, status, details)
