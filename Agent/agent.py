import os
import time
import json
import platform
import subprocess
import socket
import urllib.request
import urllib.error

# Configuration
FASTAPI_URL = "http://192.168.100.30:8001/api/v1/logs" # FastAPI URL
POLL_INTERVAL = 5  # Time in seconds between log checks
AGENT_ID = f"agent-{socket.gethostname()}"
CURRENT_OS = platform.system()  # Windows or Linux

last_windows_time = None
last_linux_pos = 0
access_log_path = None
last_access_log_pos = 0

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
        pass # Fall back to legacy file reading if needed
        
    return logs

def get_linux_access_logs():
    """Reads new entries from Apache or Nginx access.log."""
    global access_log_path, last_access_log_pos
    logs = []
    
    if not access_log_path or not os.path.exists(access_log_path):
        return logs
        
    try:
        with open(access_log_path, "r") as f:
            f.seek(last_access_log_pos)
            new_data = f.read()
            last_access_log_pos = f.tell()
            
            if new_data.strip():
                logs = [line.strip() for line in new_data.split('\n') if line.strip()]
    except Exception as e:
        print(f"[!] Access Log Error: {e}")
        
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
    
    # Initialize file pointers for Linux
    if CURRENT_OS == "Linux":
        global last_linux_pos, access_log_path, last_access_log_pos
        
        # Initialize auth.log fallback pointer
        for path in ["/var/log/auth.log", "/var/log/syslog"]:
            try:
                if os.path.exists(path):
                    with open(path, "r") as f:
                        f.seek(0, 2)
                        last_linux_pos = f.tell()
                    break
            except Exception:
                continue
                
        # Initialize access.log pointer
        for path in ["/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log"]:
            try:
                if os.path.exists(path):
                    access_log_path = path
                    with open(path, "r") as f:
                        f.seek(0, 2)
                        last_access_log_pos = f.tell()
                    print(f"[*] Monitoring access log: {access_log_path}")
                    break
            except Exception:
                continue

    while True:
        if CURRENT_OS == "Windows":
            logs = get_windows_sysmon_logs()
        else:
            logs = get_linux_auth_logs()
            logs.extend(get_linux_access_logs())
            
        if logs:
            send_payload(logs)
            
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
