import time
import re
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

# Initialize FastAPI
app = FastAPI(title="D.O.O.M. API")

iplist = [] # initialize the list of ip addresses sending requests

# Initialize attack count
sql_attacks = 0
malwares = 0
brute_force_attacks = 0
request_dict = {} 
start_time = time.time()

# from the of sql injection payloads file, make a list of those payloads
sqlPayloads = []
try:
    with open("sqlinjectionpayloads.txt","r") as f:
        for each in f:
            if each.strip():
                sqlPayloads.append(each.strip())
except FileNotFoundError:
    print("Warning: sqlinjectionpayloads.txt not found. Create it to detect SQLi.")
            
# from the malware keywords file, make a list of those payloads
malwarePayloads = []
try:
    with open("malwarepayloads.txt","r") as f:
        for each in f:
            if each.strip():
                malwarePayloads.append(each.strip())
except FileNotFoundError:
    print("Warning: malwarepayloads.txt not found. Create it to detect Malware.")

# D.O.O.M. JSON Payload Structure
class LogBatch(BaseModel):
    doombot_id: str
    os: str
    logs: list[str]

def bruteforce(line, request, ip):
    global brute_force_attacks
    message = ""
            
    if not line:
        return 1
            
    # Check for brute force
    date = re.search(r"\b[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}\b",line)
    if not date:
        date = re.search(r"\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}",line)
        if not date:
            date = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",line) # Windows format
            if not date:
                date = "Couldn't resolve date"
            else:
                date = date.group()
        else:
            date = date.group()
    else:
        date = date.group()
        
    # Check if login was successful
    if "Accepted password" in line or "4624" in line: # 4624 is Windows Success
        message = f"{date} Login alert: {ip} successfully logged in."
    
    # Check for Linux SSH fails OR Windows Event ID 4625 (Failed Logon)
    elif "Invalid user" in line or "Failed password" in line or "4625" in line:
        #check for number of requests
        if ip in request:
            request[ip] += 1 # Increment the count of ip
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


# Post logs
@app.post("/api/v1/logs")
async def ingest_logs(batch: LogBatch):
    global start_time, request_dict
    
    threat_detected = False # Used to trigger the ESP32 LED
    
    # clear request dictionary after 5 seconds
    current_time = time.time()
    if current_time - start_time > 5:
        request_dict = {}
        start_time = time.time()
            
    # Process each log sent by the ESP32
    for line in batch.logs:
        ip = "Unknown IP" # Default fallback for local Sysmon logs without remote IPs
        
        # get ip address
        patterns = [
            r"(?i)(?:from|src|client|remote(?:_| )?addr|remote-ip)[=: ]*(\d{1,3}(?:\.\d{1,3}){3})",
            r"(\d{1,3}(?:\.\d{1,3}){3}) - -",
            r"(\d{1,3}(?:\.\d{1,3}){3})[^0-9.]",           # IP followed by non-IP char
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",        # standalone anywhere (last resort)
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
                    
        # bruteforce check
        message = bruteforce(line, request_dict, ip)
        if message != 1:
            print(line)
            if message != "":
                threat_detected = True
                with open("alerts.txt","a") as f:
                    f.write(f"[{batch.doombot_id} - {batch.os}] {message}\n")
        
        # sqlinjection check
        message = sqlinjection(line, sqlPayloads, ip)
        if message != 1:
            if message != "":
                threat_detected = True
                with open("alerts.txt","a") as f:
                    f.write(f"[{batch.doombot_id} - {batch.os}] {message}\n")
                    
        # malwaredetection check
        message = malwaredetection(line, malwarePayloads, ip)
        if message != 1:
            if message != "":
                threat_detected = True
                with open("alerts.txt","a") as f:
                    f.write(f"[{batch.doombot_id} - {batch.os}] {message}\n")

    # Send the response back to the ESP32 to control the Red LED
    return {
        "status": "success", 
        "threat_detected": threat_detected
    }

if __name__ == "__main__":
    # Start the FastAPI server on port 8000
    uvicorn.run(app, host="0.0.0.0", port=8000)
