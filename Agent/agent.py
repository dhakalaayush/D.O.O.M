import os
import time
import json
import platform
import subprocess
import socket
import urllib.request
import urllib.error

# Configuration
FASTAPI_URL = "http://192.168.100.30:8001/api/v1/logs" #FastAPI URL
POLL_INTERVAL = 5  # Time in seconds between log checks
AGENT_ID = f"agent-{socket.gethostname()}"
CURRENT_OS = platform.system()  # Windows or Linux

last_windows_time = None
last_linux_pos = 0

def get_windows_sysmon_logs():
    """Queries Windows Sysmon logs newer than the last check."""
    global last_windows_time
    logs = []
    
    # PowerShell command to take the latest 5 Sysmon logs
    ps_cmd = (
        'Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 '
        '-ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message'
    )
    
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.stdout:
            # Split raw message blocks
            raw_entries = [entry.strip() for entry in result.stdout.split("\r\n\r\n") if entry.strip()]
            logs = raw_entries
    except Exception as e:
        print(f"[!] Windows Log Error: {e}")
        
    return logs

def get_linux_auth_logs():
    """Queries Linux auth logs via journalctl (for modern systemd) or auth.log (legacy)."""
    global last_linux_pos
    logs = []
    
    # Read systemd journalctl
    try:
        # SYSLOG_FACILITY=10 maps to authpriv
        cmd = [
            "journalctl", 
            "SYSLOG_FACILITY=10", 
            "--since", f"{POLL_INTERVAL} seconds ago", 
            "--no-pager", 
            "-q"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout.strip():
            logs = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            if logs:
                return logs
    except Exception:
        pass # If journalctl fails, fall back to reading text files
        
    return logs

def send_payload(logs):
    """Sends the formatted JSON batch to FastAPI using standard urllib."""
    if not logs:
        return
        
    payload = {
        "doombot_id": AGENT_ID,
        "os": CURRENT_OS,
        "logs": logs
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        FASTAPI_URL,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                res_body = json.loads(response.read().decode())
                if res_body.get("threat_detected"):
                    print(f"[ALERT] FastAPI flagged a threat on this host!")
                else:
                    print(f"[*] Ingested {len(logs)} logs. Status: Normal")
    except urllib.error.URLError as e:
        print(f"[!] Failed to reach FastAPI server: {e.reason}")

def main():
    print(f"==================================================")
    print(f" D.O.O.M. Software Agent Active")
    print(f" Host: {socket.gethostname()} | OS: {CURRENT_OS}")
    print(f" Target Server: {FASTAPI_URL}")
    print(f"==================================================")
    
    # Initialize file pointer for Linux
    if CURRENT_OS == "Linux":
        global last_linux_pos
        for path in ["/var/log/auth.log", "/var/log/syslog"]:
            try:
                if os.path.exists(path):
                    with open(path, "r") as f:
                        f.seek(0, 2)
                        last_linux_pos = f.tell()
                    break
            except Exception:
                continue

    while True:
        if CURRENT_OS == "Windows":
            logs = get_windows_sysmon_logs()
        else:
            logs = get_linux_auth_logs()
            
        if logs:
            send_payload(logs)
            
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
