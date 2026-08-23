import time
import json
import platform
import subprocess
import socket
import urllib.request
import urllib.error

# Configuration
FASTAPI_URL = "URL"  # Change to your FastAPI Server IP
POLL_INTERVAL = 5  # Time in seconds between log checks
AGENT_ID = f"agent-{socket.gethostname()}"
CURRENT_OS = platform.system()  # Windows or Linux


last_windows_time = None
last_linux_pos = 0

def get_windows_sysmon_logs():
    """Queries Windows Sysmon logs newer than the last check."""
    global last_windows_time
    logs = []
    
    # PowerShell command to grab the latest 5 Sysmon logs
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
    """Tails /var/log/auth.log from the last read file offset."""
    global last_linux_pos
    log_file_path = "/var/log/auth.log"
    logs = []
    
    try:
        with open(log_file_path, "r") as f:
            f.seek(last_linux_pos)
            lines = f.readlines()
            last_linux_pos = f.tell()
            logs = [line.strip() for line in lines if line.strip()]
    except FileNotFoundError:
        # Fallback to syslog if auth.log is not present
        try:
            with open("/var/log/syslog", "r") as f:
                f.seek(last_linux_pos)
                lines = f.readlines()
                last_linux_pos = f.tell()
                logs = [line.strip() for line in lines if line.strip()]
        except Exception as e:
            print(f"[!] Linux Log Error: {e}")
    except PermissionError:
        print("[!] Error: Agent requires sudo/root permissions to read /var/log/auth.log")
        
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
    
    # Initialize file pointer for Linux so we don't dump the whole history on startup
    if CURRENT_OS == "Linux":
        global last_linux_pos
        for path in ["/var/log/auth.log", "/var/log/syslog"]:
            try:
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
