import time
import json
import psutil
import requests
import subprocess
import socket
from datetime import datetime

SOC_SERVER_URL = "http://192.168.56.101:5000/event"
AGENT_ID = socket.gethostname()
SUSPICIOUS_TOOLS = ["nmap", "hydra", "sqlmap", "masscan", "nikto", "john", "netcat", "nc"]

def get_timestamp():
    return datetime.utcnow().isoformat() + "Z"

def send_event(event_type, severity, message):
    event = {
        "event_type": event_type,
        "severity": severity,
        "source": AGENT_ID,
        "message": message,
        "timestamp": get_timestamp()
    }
    try:
        requests.post(SOC_SERVER_URL, json=event, timeout=2)
        print(f"[*] Sent event: {event_type} - {severity}")
    except Exception as e:
        print(f"[!] Failed to send event to SOC server: {e}")

def monitor_cpu():
    cpu_usage = psutil.cpu_percent(interval=1)
    if cpu_usage > 90.0:
        send_event("system_anomaly", "MEDIUM", f"High CPU usage detected: {cpu_usage}%")

def monitor_processes():
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            name = proc.info.get('name', '').lower()
            cmdline = proc.info.get('cmdline', [])
            cmd_str = " ".join(cmdline).lower() if cmdline else ""
            
            for tool in SUSPICIOUS_TOOLS:
                if tool in name or (tool in cmd_str and tool != "nc" and tool != "john"):
                    # Strict match for short names
                    if tool == "nc" and " nc " not in f" {cmd_str} " and name != "nc":
                        continue
                    if tool == "john" and " john " not in f" {cmd_str} " and name != "john":
                         continue
                    
                    send_event("suspicious_process", "HIGH", f"Suspicious process detected: {name} (PID: {proc.info['pid']}) - Cmd: {cmd_str}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def monitor_connections():
    try:
        output = subprocess.check_output(['ss', '-tan'], text=True)
        lines = output.split('\n')
        connections = []
        for line in lines[1:]: # Skip header
            parts = line.split()
            if len(parts) >= 5:
                state = parts[0]
                local = parts[3]
                peer = parts[4]
                if peer != "0.0.0.0:*":
                    connections.append({"state": state, "local": local, "peer": peer})
                    
        if connections:
            send_event("network_connections", "INFO", json.dumps(connections))
            
    except Exception as e:
        print(f"[!] Network monitoring error: {e}")

if __name__ == "__main__":
    print("[*] Starting Endpoint Monitoring Agent...")
    while True:
        monitor_cpu()
        monitor_processes()
        monitor_connections()
        time.sleep(5)
