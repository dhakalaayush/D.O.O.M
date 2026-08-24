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
request_dict = {} 
start_time = time.time()

# Load SQLi Payloads
sqlPayloads = []
try:
    with open("sqlinjectionpayloads.txt","r") as f:
        for each in f:
            if each.strip():
                sqlPayloads.append(each.strip())
except FileNotFoundError:
    print("Warning: sqlinjectionpayloads.txt not found. SQLi detection disabled.")
            
# Load Malware Payloads
malwarePayloads = []
try:
    with open("malwarepayloads.txt","r") as f:
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

# Detection Logics

def bruteforce(line, request, ip):
    global brute_force_attacks
    message = ""
            
    if not line:
        return 1
            
    # Resolve Date (Includes Windows format)
    date = re.search(r"\b[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}\b",line)
    if not date:
        date = re.search(r"\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}",line)
        if not date:
            date = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",line) 
            if not date:
                date = "Couldn't resolve date"
            else:
                date = date.group()
        else:
            date = date.group()
    else:
        date = date.group()
        
    # Check successful login (Linux or Windows 4624)
    if "Accepted password" in line or "4624" in line: 
        message = f"{date} Login alert: {ip} successfully logged in."
    
    # Check failed login (Linux or Windows 4625)
    elif "Invalid user" in line or "Failed password" in line or "4625" in line:
        if ip in request:
            request[ip] += 1
        elif ip not in request:
            request[ip] = 1
            
        if request[ip] > 3:
            brute_force_attacks += 1
            message = f"{date} Multiple failed login attempts from {ip}. Potential Brute Force alert"
                    
    return message if message else 1

def sqlinjection(line, payloads, ip):
    global sql_attacks
    for each in payloads:
        if each.lower() in line.lower():
            date = re.search(r"\b[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}\b",line)
            if not date:
                date = "Couldn't resolve date"
            else:
                date = date.group()
            sql_attacks += 1
            return f"{date} SQL Injection alert from {ip}!"
    return 1

def malwaredetection(line, payloads, ip):
    global malwares
    for each in payloads:
        if each.lower() in line.lower():
            date = re.search(r"\b[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}\b",line)
            if not date:
                date = "Couldn't resolve date"
            else:
                date = date.group()
            malwares += 1
            return f"{date} Suspicious Action alert from {ip}!"
    return 1

def ipbook(ip):
    global iplist
    if ip not in iplist:
        iplist.append(ip)
    return iplist

# API ENDPOINT
@app.post("/api/v1/logs")
async def ingest_logs(batch: LogBatch):
    global start_time, request_dict
    
    threat_detected = False 
    
    # Reset brute force tracker every 5 seconds
    current_time = time.time()
    if current_time - start_time > 5:
        request_dict = {}
        start_time = time.time()
            
    # Process incoming batch
    for line in batch.logs:
        ip = "Unknown IP" 
        
        # Archive the raw log for the frontend
        with open("archive_logs.txt", "a") as archive:
            # Format: OS | DoombotID | Raw Log
            archive.write(f"{batch.os}|{batch.doombot_id}|{line}\n")
        
        # Extract IP address
        patterns = [
            r"(?i)(?:from|src|client|remote(?:_| )?addr|remote-ip)[=: ]*(\d{1,3}(?:\.\d{1,3}){3})",
            r"(\d{1,3}(?:\.\d{1,3}){3}) - -",
            r"(\d{1,3}(?:\.\d{1,3}){3})[^0-9.]",           
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",        
        ]
        
        for pat in patterns:
            m = re.search(pat, line, re.IGNORECASE)
            if m:
                ip = m.group(1).strip()
                break
                
        if ip != "Unknown IP":
            iplist = ipbook(ip)
            with open("ip.txt", "a+") as f:
                f.seek(0)
                existing_ips = set(line.strip() for line in f.readlines())
                new_ips = [each for each in iplist if each not in existing_ips]
                for ip_addr in new_ips:
                    f.write(f"{ip_addr}\n")
                    
        # Threat Scanning
        message = bruteforce(line, request_dict, ip)
        if message != 1 and message != "":
            threat_detected = True
            with open("alerts.txt","a") as f:
                f.write(f"[{batch.doombot_id} - {batch.os}] {message}\n")
        
        message = sqlinjection(line, sqlPayloads, ip)
        if message != 1 and message != "":
            threat_detected = True
            with open("alerts.txt","a") as f:
                f.write(f"[{batch.doombot_id} - {batch.os}] {message}\n")
                    
        message = malwaredetection(line, malwarePayloads, ip)
        if message != 1 and message != "":
            threat_detected = True
            with open("alerts.txt","a") as f:
                f.write(f"[{batch.doombot_id} - {batch.os}] {message}\n")

    # Hardware Feedback Loop
    if threat_detected:
        print(f"[{batch.doombot_id}] THREAT DETECTED. Instructing Doombot: RED LED ON")
    else:
        print(f"[{batch.doombot_id}] Status clear. Instructing Doombot: GREEN LED ON")

    return {
        "status": "success", 
        "threat_detected": threat_detected
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
