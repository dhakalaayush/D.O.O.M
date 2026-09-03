import time
import re
import os
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

# Initialize FastAPI
app = FastAPI(title="D.O.O.M. API")

iplist = [] 
sql_attacks = 0
malwares = 0
brute_force_attacks = 0

# Store timestamps
request_dict = {} 

# Load SQLi Payloads
sqlPayloads = []
try:
    with open("sqlinjectionpayloads.txt", "r") as f:
        for each in f:
            if each.strip():
                sqlPayloads.append(each.strip())
except FileNotFoundError:
    print("Warning: sqlinjectionpayloads.txt not found. SQLi detection disabled.")
            
# Load Malware Payloads
malwarePayloads = []
try:
    with open("malwarepayloads.txt", "r") as f:
        for each in f:
            if each.strip():
                malwarePayloads.append(each.strip())
except FileNotFoundError:
    print("Warning: malwarepayloads.txt not found. Malware detection disabled.")

# Incoming Data Schema
class LogBatch(BaseModel):
    doombot_id: str
    os: str
    logs: list[str]



# Detection Logic

def bruteforce(line, ip, tracker, window_seconds=60, threshold=3):
    """
    Sliding window brute force detector.
    Flags an alert if more than `threshold` failed attempts occur within `window_seconds`.
    """
    global brute_force_attacks
    if not line:
        return 1

    line_lower = line.lower()
    
    # Check for authentication failure keywords
    failure_keywords = [
        "failed password",
        "invalid user",
        "authentication failure",
        "failed login",
        "check pass; user unknown",
        "password check failed",
        "4625"  # Windows Event ID for failed logon
    ]
    
    is_failed = any(kw in line_lower for kw in failure_keywords)
    
    if is_failed:
        # Resolve Date
        date_match = re.search(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b", line)
        if not date_match:
            date_match = re.search(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", line)
        date = date_match.group() if date_match else "Timestamp N/A"

        now = time.time()
        
        # Timestamp
        if ip not in tracker:
            tracker[ip] = []
            
        tracker[ip].append(now)
        
        # Clean old attempts
        tracker[ip] = [t for t in tracker[ip] if now - t <= window_seconds]
        
        if len(tracker[ip]) >= threshold:
            brute_force_attacks += 1
            return f"{date} Multiple failed login attempts from {ip} ({len(tracker[ip])} attempts). Potential Brute Force alert"
            
    return 1

def sqlinjection(line, payloads, ip):
    global sql_attacks
    if not payloads:
        return 1
        
    line_lower = line.lower()
    for each in payloads:
        if each.lower() in line_lower:
            date_match = re.search(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b", line)
            date = date_match.group() if date_match else "Timestamp N/A"
            sql_attacks += 1
            return f"{date} SQL Injection alert from {ip}!"
    return 1

def malwaredetection(line, payloads, ip):
    global malwares
    if not payloads:
        return 1
        
    line_lower = line.lower()
    for each in payloads:
        if each.lower() in line_lower:
            date_match = re.search(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b", line)
            date = date_match.group() if date_match else "Timestamp N/A"
            malwares += 1
            return f"{date} Suspicious Action alert from {ip}!"
    return 1

def ipbook(ip):
    global iplist
    if ip not in iplist:
        iplist.append(ip)
    return iplist

# API Endpoint

@app.post("/api/v1/logs")
async def ingest_logs(batch: LogBatch):
    global request_dict
    
    threat_detected = False 
    
    # Process incoming batch
    for line in batch.logs:
        ip = "Unknown IP" 
        
        # Archive the raw log
        with open("archive_logs.txt", "a", encoding="utf-8") as archive:
            archive.write(f"{batch.os}|{batch.doombot_id}|{line}\n")
        
        # Extract IP address
        patterns = [
            r"(?i)(?:from|src|client|remote(?:_| )?addr|remote-ip)[=: ]*(\d{1,3}(?:\.\d{1,3}){3})",
            r"(\d{1,3}(?:\.\d{1,3}){3}) - -",
            r"rhost=(\d{1,3}(?:\.\d{1,3}){3})",
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        ]
        
        for pat in patterns:
            m = re.search(pat, line, re.IGNORECASE)
            if m:
                ip = m.group(1).strip()
                break
                
        if ip != "Unknown IP":
            ipbook(ip)
            with open("ip.txt", "a+", encoding="utf-8") as f:
                f.seek(0)
                existing_ips = set(l.strip() for l in f.readlines())
                if ip not in existing_ips:
                    f.write(f"{ip}\n")

        # IP
        entity_key = ip if ip != "Unknown IP" else batch.doombot_id

        # Brute Force Scan
        bf_msg = bruteforce(line, entity_key, request_dict, window_seconds=60, threshold=3)
        if bf_msg != 1 and bf_msg != "":
            threat_detected = True
            with open("alerts.txt", "a", encoding="utf-8") as f:
                f.write(f"[{batch.doombot_id} - {batch.os}] {bf_msg}\n")
        
        # SQLi Scan
        sqli_msg = sqlinjection(line, sqlPayloads, ip)
        if sqli_msg != 1 and sqli_msg != "":
            threat_detected = True
            with open("alerts.txt", "a", encoding="utf-8") as f:
                f.write(f"[{batch.doombot_id} - {batch.os}] {sqli_msg}\n")
                    
        # Malware Scan
        mal_msg = malwaredetection(line, malwarePayloads, ip)
        if mal_msg != 1 and mal_msg != "":
            threat_detected = True
            with open("alerts.txt", "a", encoding="utf-8") as f:
                f.write(f"[{batch.doombot_id} - {batch.os}] {mal_msg}\n")

    # Feedback loop for esp32
    if threat_detected:
        print(f"[{batch.doombot_id}] THREAT DETECTED. Instructing Doombot: RED LED ON")
    else:
        print(f"[{batch.doombot_id}] Status clear. Instructing Doombot: GREEN LED ON")

    return {
        "status": "success", 
        "threat_detected": threat_detected
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
