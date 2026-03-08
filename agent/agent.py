#!/usr/bin/env python3
"""
SOC Endpoint Monitoring Agent
Runs on the User/Victim VM (192.168.56.103)
Sends telemetry to the SOC Server and receives response commands.

Configuration:
  Set the environment variable SOC_SERVER_URL to point at your server.
  Default: http://192.168.56.101:5000  (local lab)
  Example: export SOC_SERVER_URL=https://your-app.onrender.com
"""

import os
import sys
import time
import json
import socket
import subprocess
import psutil
import requests
from datetime import datetime, timezone

# ─── Config ───────────────────────────────────────────────────────────────
SOC_SERVER_URL = os.environ.get("SOC_SERVER_URL", "http://192.168.56.101:5000")
AGENT_ID       = socket.gethostname()
INTERVAL       = 6  # seconds between polling loops

SUSPICIOUS_PROCS = {"nmap", "hydra", "sqlmap", "masscan", "nikto", "john", "netcat", "nc"}

# ─── Helpers ──────────────────────────────────────────────────────────────

def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def send_event(event_type, severity, message):
    payload = {
        "event_type": event_type,
        "severity":   severity,
        "source":     AGENT_ID,
        "message":    message,
        "timestamp":  now_utc(),
    }
    try:
        resp = requests.post(f"{SOC_SERVER_URL}/event", json=payload, timeout=5)
        data = resp.json()
        print(f"[*] Sent event: {event_type} - {severity}")

        # Execute any queued response actions returned by the server
        for action in data.get("actions", []):
            execute_response_action(action)

    except requests.RequestException as e:
        print(f"[!] Error sending event: {e}")


def execute_response_action(action):
    action_type = action.get("type")
    target      = action.get("target")

    if action_type == "iptables_block":
        print(f"[!] EXECUTING ACTIVE RESPONSE: Blocking IP {target} via iptables")
        result = subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", target, "-j", "DROP"],
            capture_output=True
        )
        status  = "success" if result.returncode == 0 else "failed"
        details = result.stderr.decode().strip() if result.returncode != 0 else ""
        send_event("response_executed", "INFO",
                   f"iptables_block {target}: {status} {details}")

    elif action_type == "kill_process":
        print(f"[!] EXECUTING ACTIVE RESPONSE: Killing process '{target}'")
        killed = False
        for proc in psutil.process_iter(["name", "pid"]):
            if proc.info["name"] and target.lower() in proc.info["name"].lower():
                try:
                    proc.kill()
                    killed = True
                    print(f"    Killed PID {proc.info['pid']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        status = "success" if killed else "not_found"
        send_event("response_executed", "INFO", f"kill_process {target}: {status}")

# ─── Monitors ─────────────────────────────────────────────────────────────

def monitor_processes():
    for proc in psutil.process_iter(["name", "pid", "cmdline"]):
        try:
            name = proc.info["name"] or ""
            if name.lower() in SUSPICIOUS_PROCS:
                cmd = " ".join(proc.info.get("cmdline") or [name])
                print(f"[!] EXECUTING ACTIVE PREVENTION: Killing malicious process {name} (PID: {proc.info['pid']})")
                proc.kill()
                send_event("suspicious_process", "HIGH",
                           f"Suspicious process detected: {name} (PID: {proc.info['pid']}) - Cmd: {cmd}")
                send_event("prevention_action", "INFO",
                           f"Killed process {name} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


def monitor_network():
    try:
        result = subprocess.run(["ss", "-tan"], capture_output=True, text=True)
        lines  = result.stdout.strip().split("\n")[1:]
        connections = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                connections.append({"state": parts[0], "local": parts[3], "peer": parts[4]})
        send_event("network_connections", "INFO", json.dumps(connections))
    except Exception as e:
        print(f"[!] Network monitor error: {e}")


def monitor_cpu():
    cpu = psutil.cpu_percent(interval=1)
    if cpu > 90:
        send_event("system_anomaly", "HIGH", f"CPU spike: {cpu:.1f}%")
    else:
        send_event("system_anomaly", "INFO", f"CPU normal: {cpu:.1f}%")

# ─── Main Loop ─────────────────────────────────────────────────────────────

def main():
    print(f"[*] Starting Endpoint Monitoring Agent...")
    print(f"[*] Agent ID  : {AGENT_ID}")
    print(f"[*] SOC Server: {SOC_SERVER_URL}")
    print(f"[*] Interval  : {INTERVAL}s\n")

    while True:
        try:
            monitor_processes()
            monitor_network()
            monitor_cpu()
        except Exception as e:
            print(f"[!] Loop error: {e}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
