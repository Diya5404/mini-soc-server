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

# Ports that the VM doesn't legitimately use, but attackers often scan
HONEYPOT_PORTS = [21, 23, 1433, 3306, 8080]

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
    """
    Collect all TCP connections using psutil (primary) or ss -tan (fallback).
    psutil captures SYN_RECV states from nmap SYN scans that ss may miss.
    """
    connections = []
    try:
        for c in psutil.net_connections(kind="tcp"):
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            connections.append({
                "state": c.status or "UNKNOWN",
                "local": laddr,
                "peer":  raddr,
            })
    except Exception:
        # Fallback to ss -tan
        try:
            result = subprocess.run(["ss", "-tan"], capture_output=True, text=True)
            lines  = result.stdout.strip().split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    connections.append({
                        "state": parts[0],
                        "local": parts[3],
                        "peer":  parts[4],
                    })
        except Exception as e:
            print(f"[!] Network monitor error: {e}")

    send_event("network_connections", "INFO", json.dumps(connections))


def monitor_cpu():
    cpu = psutil.cpu_percent(interval=1)
    if cpu > 90:
        send_event("system_anomaly", "HIGH", f"CPU spike: {cpu:.1f}%")
    else:
        send_event("system_anomaly", "INFO", f"CPU normal: {cpu:.1f}%")

# ─── Honeypots ────────────────────────────────────────────────────────────

def honeypot_listener(port):
    """Listens on a fake port. Any connection is a guaranteed scan/probe."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(5)
        while True:
            conn, addr = s.accept()
            peer_ip = addr[0]
            conn.close()
            print(f"[!] HONEYPOT TRIPPED on port {port} by {peer_ip}")
            send_event("port_scan_detected", "HIGH", 
                       f"HIGH SEVERITY: Honeypot tripped on port {port} from {peer_ip}")
            # Rate limit the specific honeypot log to avoid flooding from a single scan
            time.sleep(2)
    except Exception as e:
        print(f"[-] Could not start honeypot on port {port}: {e}")

def monitor_auth_log():
    """Tails /var/log/auth.log to immediately catch failed SSH logins."""
    log_file = "/var/log/auth.log"
    if not os.path.exists(log_file) or not os.access(log_file, os.R_OK):
        print(f"[-] Cannot read {log_file} - SSH monitoring disabled.")
        return

    try:
        with open(log_file, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                if "sshd" in line and "Failed password" in line:
                    # Extract IP address. Format typically: "Failed password for root from 192.168.1.5 port ..."
                    parts = line.split()
                    try:
                        ip_index = parts.index("from") + 1
                        attacker_ip = parts[ip_index]
                        print(f"[!] SSH Brute Force attempt detected from {attacker_ip}")
                        send_event("ssh_bruteforce_detected", "HIGH",
                                   f"HIGH SEVERITY: Failed SSH login from {attacker_ip}")
                    except ValueError:
                        pass
    except Exception as e:
        print(f"[-] Error parsing auth.log: {e}")

def start_background_monitors():
    import threading
    
    # Honeypots
    for port in HONEYPOT_PORTS:
        t = threading.Thread(target=honeypot_listener, args=(port,), daemon=True)
        t.start()
        print(f"[*] Started Honeypot listener on port {port}")
        
    # SSH Logger
    t_ssh = threading.Thread(target=monitor_auth_log, daemon=True)
    t_ssh.start()
    print(f"[*] Started SSH Auth Logger")

# ─── Main Loop ─────────────────────────────────────────────────────────────

def main():
    print(f"[*] Starting Endpoint Monitoring Agent...")
    print(f"[*] Agent ID  : {AGENT_ID}")
    print(f"[*] SOC Server: {SOC_SERVER_URL}")
    print(f"[*] Interval  : {INTERVAL}s\n")
    
    start_background_monitors()

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
