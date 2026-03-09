import sqlite3
import os
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "soc.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables if they do not already exist."""
    conn = get_conn()
    c = conn.cursor()
    
    # Enable WAL mode for better concurrency
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")

    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            severity TEXT,
            source TEXT,
            message TEXT,
            timestamp TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            message TEXT,
            source TEXT,
            threat_score INTEGER,
            mitre_technique TEXT,
            mitre_name TEXT,
            timestamp TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT,
            message TEXT,
            threat_score INTEGER,
            mitre_technique TEXT,
            timestamp TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            action_type TEXT,
            target TEXT,
            status TEXT,
            details TEXT,
            timestamp TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS response_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            action_type TEXT,
            target TEXT,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()


# ─── Events ────────────────────────────────────────────────────────────────

def insert_event(event):
    conn = get_conn()
    conn.execute(
        "INSERT INTO events (event_type, severity, source, message, timestamp) VALUES (?,?,?,?,?)",
        (event.get("event_type"), event.get("severity"), event.get("source"),
         str(event.get("message", "")), event.get("timestamp"))
    )
    conn.commit()
    conn.close()


def get_events(limit=200):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Alerts ────────────────────────────────────────────────────────────────

def insert_alert(alert):
    conn = get_conn()
    conn.execute(
        """INSERT INTO alerts
           (alert_type, severity, message, source, threat_score, mitre_technique, mitre_name, timestamp)
           VALUES (?,?,?,?,?,?,?,?)""",
        (alert.get("alert_type"), alert.get("severity"), alert.get("message"),
         alert.get("source"), alert.get("threat_score"),
         alert.get("mitre_technique"), alert.get("mitre_name"), alert.get("timestamp"))
    )
    conn.commit()
    conn.close()


def get_alerts(limit=200):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Incidents ─────────────────────────────────────────────────────────────

def insert_incident(incident):
    conn = get_conn()
    conn.execute(
        """INSERT INTO incidents (severity, message, threat_score, mitre_technique, timestamp)
           VALUES (?,?,?,?,?)""",
        (incident.get("severity"), incident.get("message"),
         incident.get("threat_score"), incident.get("mitre_technique"), incident.get("timestamp"))
    )
    conn.commit()
    conn.close()


def get_incidents(limit=200):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Responses ─────────────────────────────────────────────────────────────

def log_response(agent_id, action_type, target, status, details):
    conn = get_conn()
    conn.execute(
        """INSERT INTO responses (agent_id, action_type, target, status, details, timestamp)
           VALUES (?,?,?,?,?,?)""",
        (agent_id, action_type, target, status, details, datetime.utcnow().isoformat() + "Z")
    )
    conn.commit()
    conn.close()


def get_responses(limit=200):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM responses ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Response Queue ─────────────────────────────────────────────────────────

def queue_action(agent_id, action_type, target):
    conn = get_conn()
    # Avoid duplicates
    existing = conn.execute(
        "SELECT id FROM response_queue WHERE agent_id=? AND action_type=? AND target=?",
        (agent_id, action_type, target)
    ).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO response_queue (agent_id, action_type, target, timestamp) VALUES (?,?,?,?)",
            (agent_id, action_type, target, datetime.utcnow().isoformat() + "Z")
        )
        conn.commit()
    conn.close()


def get_pending_actions(agent_id):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM response_queue WHERE agent_id=?", (agent_id,)
    ).fetchall()
    if rows:
        ids = [r["id"] for r in rows]
        conn.execute(f"DELETE FROM response_queue WHERE id IN ({','.join('?'*len(ids))})", ids)
        conn.commit()
    conn.close()
    return [{"type": r["action_type"], "target": r["target"], "timestamp": r["timestamp"]} for r in rows]


# Initialise on import
init_db()
