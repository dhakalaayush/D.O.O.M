import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import re
import time
import json
import google.generativeai as genai

# Page Setup
st.set_page_config(page_title="D.O.O.M. SIEM", layout="wide", initial_sidebar_state="collapsed")

# Initialize AI Cache
if 'boris_cache' not in st.session_state:
    st.session_state.boris_cache = {}

st.markdown("""
<style>
    .stApp { background-color: #011f02; color: white; }
    h1, h2, h3, h4 { color: #f8fafc; font-weight: 600; }
    hr { border-color: #334155; margin: 24px 0; }
    .boris-banner { background-color: #001a02; padding: 24px; border-radius: 12px; border: 1px solid #334155; margin-top: 16px; }
    .custom-table { width: 100%; border-collapse: collapse; font-family: sans-serif; border: 1px solid #334155; border-radius: 8px; overflow: hidden; }
    .custom-table th { background-color: #001a02; color: #94a3b8; border: none; border-bottom: 1px solid #334155; padding: 12px 16px; text-align: left; font-weight: 600; }
    .custom-table td { background-color: #011f02; color: white; border: none; border-bottom: 1px solid #1a301b; padding: 12px 16px; }
</style>
""", unsafe_allow_html=True)

# AI Setup
try:
    with open("gemini_key.txt", "r") as f:
        GEMINI_API_KEY = f.read().strip()
    genai.configure(api_key=GEMINI_API_KEY)
    ai_enabled = True
except FileNotFoundError:
    GEMINI_API_KEY = None
    ai_enabled = False
    print("Error fetching AI.")

def get_boris_assessment(details, os_type):
    """Prompts Gemini to generate a full structured triage assessment."""
    if not ai_enabled:
        return {
            "alert_name": "Uncategorized Threat", "severity": "MEDIUM", 
            "cvss": "N/A", "epss": "N/A", "vpr": "N/A", 
            "mitigation": "Offline Mode: Isolate host and consult local DFIR playbook."
        }
        
    try:
        # Force the AI to return a clean JSON object
        model = genai.GenerativeModel('gemini-3.6-flash', generation_config={"response_mime_type": "application/json"})
        prompt = f"""
        You are Boris, an expert cybersecurity AI assistant embedded in a custom SIEM.
        Analyze this security event on a {os_type} machine: "{details}"
        
        Provide a JSON response with EXACTLY these keys:
        - "alert_name": A short, clinical name for the threat (e.g., "SSH Brute Force", "SQL Injection").
        - "severity": Must be exactly "HIGH", "MEDIUM", or "LOW".
        - "cvss": Estimated CVSS 3.1 score out of 10 (e.g., "7.5", "9.8"). You MUST provide a numerical estimate, never output "N/A".
        - "epss": Estimated EPSS score (e.g., "0.08"). You MUST provide a numerical estimate, never output "N/A".
        - "vpr": Estimated VPR score (e.g., "6.2"). You MUST provide a numerical estimate, never output "N/A".
        - "mitigation": A concise, actionable mitigation plan (under 3 sentences). Do not use markdown.
        """
        response = model.generate_content(prompt)
        return json.loads(response.text)
    except Exception as e:
        return {
            "alert_name": "AI Parsing Error", "severity": "MEDIUM", 
            "cvss": "N/A", "epss": "N/A", "vpr": "N/A", 
            "mitigation": f"Boris encountered a neural link error: {str(e)}"
        }

# Data Ingestion
def get_real_alerts():
    alerts = []
    target_path = "../Backend/alerts.txt"
    if not os.path.exists(target_path):
        return alerts

    with open(target_path, "r") as f:
        lines = f.readlines()

    for line in lines:
        match = re.match(r"\[(.*?) - (.*?)\] (.*)", line.strip())
        if match:
            machine_id = match.group(1)
            os_type = match.group(2)
            details = match.group(3)

            # Extract the timestamp (HH:MM:SS) from the raw log details
            time_match = re.search(r"(\d{2}:\d{2}:\d{2})", details)
            alert_time = time_match.group(1) if time_match else "Unknown"

            # Create a clean cache signature by stripping dates, IPs, and varying attempt counts
            sig = re.sub(r'\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b', '', details) # Strip Dates
            sig = re.sub(r'\d{1,3}(?:\.\d{1,3}){3}', '[IP]', sig) # Normalize IPs
            sig = re.sub(r'\(\d+\sattempts\)', '', sig) # Strip Hydra attempt counts
            cache_key = sig.strip()

            # Check AI Cache
            if cache_key in st.session_state.boris_cache:
                assessment = st.session_state.boris_cache[cache_key]
            else:
                assessment = get_boris_assessment(cache_key, os_type)
                st.session_state.boris_cache[cache_key] = assessment

            alerts.append({
                "timestamp": alert_time,
                "alert_name": assessment.get("alert_name", "Suspicious Activity"),
                "machine": machine_id,
                "os": os_type,
                "severity": assessment.get("severity", "LOW"),
                "cve_id": "Boris AI Core",
                "description": details, 
                "cvss": assessment.get("cvss", "N/A"),
                "epss": assessment.get("epss", "N/A"),
                "vpr": assessment.get("vpr", "N/A"),
                "mitigation": assessment.get("mitigation", "Investigate manually.") 
            })
    return alerts

# Parsing
def parse_raw_log(raw_log, os_type):
    """Parses raw log strings into structured fields based on OS."""
    parsed = {
        "Date": "", "Source": "", "User": "-", "RHost": "-", 
        "Domain": "-", "Logon ID": "-", "Message": raw_log
    }

    # Clean literal '\t' strings and collapse multiple spaces
    clean_log = raw_log.replace(r"\t", " ").replace("\t", " ")
    clean_log = re.sub(r'\s+', ' ', clean_log)

    if "windows" in os_type.lower():
        match = re.match(r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s+Windows Security Event\s+(\d+):\s+(.*)", clean_log)
        if match:
            parsed["Date"] = match.group(1)
            parsed["Source"] = f"Event {match.group(2)}"
            
            # Isolate the main description
            full_msg = match.group(3).strip()
            parsed["Message"] = full_msg.split("Subject:")[0].strip() if "Subject:" in full_msg else full_msg
            
            # Extract specific Windows fields
            acct_match = re.search(r"Account Name:\s*(\S+)", clean_log)
            if acct_match: parsed["User"] = acct_match.group(1)
            
            domain_match = re.search(r"Account Domain:\s*(\S+)", clean_log)
            if domain_match: parsed["Domain"] = domain_match.group(1)
            
            logon_match = re.search(r"Logon ID:\s*(\S+)", clean_log)
            if logon_match: parsed["Logon ID"] = logon_match.group(1)
            
    elif "linux" in os_type.lower():
        match = re.match(r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.*)", clean_log)
        if match:
            parsed["Date"] = match.group(1)
            parsed["Source"] = match.group(3)
            parsed["Message"] = match.group(4).strip()
            
            # Extract specific Linux fields
            rhost_match = re.search(r"rhost=(\S+)", clean_log)
            if rhost_match: parsed["RHost"] = rhost_match.group(1)
            
            user_match = re.search(r"user=(\S+)", clean_log)
            if user_match: 
                parsed["User"] = user_match.group(1)
            else:
                # Catch CRON session cases
                alt_user_match = re.search(r"user\s+([a-zA-Z0-9_-]+)", clean_log)
                if alt_user_match: parsed["User"] = alt_user_match.group(1)
                
    return parsed


def get_archive_logs():
    logs = []
    target_path = "../Backend/archive_logs.txt"
    if not os.path.exists(target_path):
        return logs
    with open(target_path, "r") as f:
        for line in f:
            parts = line.strip().split("|", 2)
            if len(parts) == 3:
                os_type, bot, raw = parts
                time_match = re.search(r"(\d{2}:\d{2}):\d{2}", raw)
                t_val = time_match.group(1) if time_match else "00:00"
                
                parsed_data = parse_raw_log(raw, os_type)
                
                logs.append({
                    "OS": os_type, 
                    "Doombot": bot, 
                    "Time": t_val, 
                    "Source": parsed_data["Source"],
                    "User": parsed_data["User"],
                    "RHost": parsed_data["RHost"],
                    "Domain": parsed_data["Domain"],
                    "Logon ID": parsed_data["Logon ID"],
                    "Message": parsed_data["Message"],
                    "Raw Log": raw 
                })
    return logs

real_alerts_data = get_real_alerts()
archive_data = get_archive_logs()


if 'bot_log_counts' not in st.session_state:
    st.session_state.bot_log_counts = {}
if 'bot_last_active' not in st.session_state:
    st.session_state.bot_last_active = {}

current_time = time.time()
current_counts = {}
fleet_records = {}
unique_bots = {} 
bot_users = {} # Track the parsed username for each bot

for log in archive_data:
    bot = log["Doombot"]
    unique_bots[bot] = log["OS"]
    current_counts[bot] = current_counts.get(bot, 0) + 1
    
    # Extract the username/account name if parsed
    if log.get("User") and log["User"] != "-":
        bot_users[bot] = log["User"]
    
for alert in real_alerts_data:
    unique_bots[alert["machine"]] = alert["os"]

fleet_records = []
for bot, os_type in unique_bots.items():
    bot_alerts = [a for a in real_alerts_data if a["machine"] == bot]
    h = sum(1 for a in bot_alerts if a["severity"] == "HIGH")
    m = sum(1 for a in bot_alerts if a["severity"] == "MEDIUM")
    l = sum(1 for a in bot_alerts if a["severity"] == "LOW")
    
    status = "inactive"
    current_bot_count = current_counts.get(bot, 0)
    previous_bot_count = st.session_state.bot_log_counts.get(bot, 0)
    
    if current_bot_count > previous_bot_count:
        st.session_state.bot_last_active[bot] = current_time
        
    st.session_state.bot_log_counts[bot] = current_bot_count
    
    last_active = st.session_state.bot_last_active.get(bot, 0)
    if (current_time - last_active) <= 600 and last_active != 0:
        status = "active"
        
    fleet_records.append({
        "Doombot": bot, "Account Name": bot_users.get(bot, "-"), "Operating System": os_type, 
        "IP Address": "DHCP Assigned", "Alerts": f"{len(bot_alerts)}", 
        "Status": status, "high": h, "medium": m, "low": l
    })

if not fleet_records:
    fleet_records = [{"Doombot": "No Data", "Account Name": "Awaiting Telemetry", "Operating System": "-", "IP Address": "-", "Alerts": "0", "Status": "inactive", "high": 0, "medium": 0, "low": 0}]

fleet_data = pd.DataFrame(fleet_records)
archive_df = pd.DataFrame(archive_data) if archive_data else pd.DataFrame(columns=["OS", "Doombot", "Time", "Raw Log"])



# Dashboard




# Boris AI
@st.dialog("Boris Threat Assessment")
def boris_popup(item):
    st.markdown(f"### {item['alert_name']}")
    st.caption(f"Reference: `{item['cve_id']}`")
    
    st.markdown("#### **Boris Description**")
    st.write(item['description'])
    
    st.divider()
    
    col1, col2, col3 = st.columns(3)
    col1.metric("CVSS Score", item['cvss'])
    col2.metric("EPSS Score", item['epss'])
    col3.metric("VPR Score", item['vpr'])
    
    st.divider()
    
    st.markdown("#### **Boris Response**")
    st.write(item['mitigation'])
    
    if st.button("Close", use_container_width=True):
        st.rerun()

# Header
col_logo, col_title, col_refresh = st.columns([1, 8, 2])
with col_logo:
    if os.path.exists("Logo.png"):
        st.image("Logo.png", width=90)
    else:
        st.markdown("```\n[ LOGO ]\n```")
with col_title:
    st.markdown("# D . O . O . M")

# Doombot Assets
st.subheader("Doombot Assets")
table_col, status_col = st.columns([3, 1])

with table_col:
    display_cols = ["Doombot", "Account Name", "Operating System", "IP Address", "Alerts", "Status"]
    st.markdown(fleet_data[display_cols].to_html(index=False, classes="custom-table"), unsafe_allow_html=True)
with status_col:
    status_counts = fleet_data["Status"].value_counts().reset_index()
    status_counts.columns = ["Status", "Count"]
    fig_status = px.pie(status_counts, names="Status", values="Count", hole=0.6, color="Status", color_discrete_map={"active": "#0C8E5C", "inactive": "#8E1D0C"})
    fig_status.update_layout(margin=dict(t=0, b=0, l=0, r=0), height=180, showlegend=True, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#cbd5e1"))
    st.plotly_chart(fig_status, use_container_width=True, key="status_donut")

# Alerts Donuts
st.subheader("Alerts")
machine_cols = st.columns(max(len(fleet_data), 1))
for idx, row in fleet_data.iterrows():
    with machine_cols[idx]:
        sev_df = pd.DataFrame({"Severity": ["HIGH", "MEDIUM", "LOW"], "Count": [row["high"], row["medium"], row["low"]]})
        if sev_df["Count"].sum() == 0:
            sev_df = pd.DataFrame({"Severity": ["NONE"], "Count": [1]})
            color_map = {"NONE": "#334155"}
        else:
            color_map = {"HIGH": "#8E1D0C", "MEDIUM": "#FFEC83", "LOW": "#0C8E5C"}
            
        fig_machine = px.pie(sev_df, names="Severity", values="Count", hole=0.6, color="Severity", color_discrete_map=color_map)
        fig_machine.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=180, showlegend=True, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#cbd5e1"))
        st.plotly_chart(fig_machine, use_container_width=True, key=f"alert_donut_{row['Doombot']}_{idx}")
        st.markdown(f"<p style='text-align: center; font-weight: bold; color: #94a3b8;'>{row['Account Name']}</p>", unsafe_allow_html=True)
st.divider()

# Threat Triage
st.subheader("Threat Triage")

h_col1, h_col2, h_col3, h_col4, h_col5 = st.columns([1.5, 3, 2.5, 2, 1.5])
h_col1.markdown("**Time**")
h_col2.markdown("**Alert**")
h_col3.markdown("**Machine**")
h_col4.markdown("**Severity**")
h_col5.markdown("**View Details**")
st.markdown("<hr style='margin: 4px 0;'/>", unsafe_allow_html=True)

if len(real_alerts_data) == 0:
    st.info("No active threats detected. Monitoring endpoints...")
else:
    # Reverse the list and slice the first 10 so newest alerts are always at the top
    recent_alerts = list(reversed(real_alerts_data))[:10]

    for idx, alert in enumerate(recent_alerts):
        c1, c2, c3, c4, c5 = st.columns([1.5, 3, 2.5, 2, 1.5])
        c1.write(alert.get("timestamp", "N/A"))
        c2.write(alert["alert_name"])
        c3.write(alert["machine"])
        c4.write(alert["severity"])
        if c5.button("● ● ●", key=f"btn_details_{idx}"):
            boris_popup(alert)
        st.markdown("<hr style='margin: 4px 0;'/>", unsafe_allow_html=True)

st.divider()

# Doombots Archive 
st.subheader("Doombots Archive")
machine_options = [f"{bot} ({os})" for bot, os in unique_bots.items()] if unique_bots else ["No telemetry found"]
selected_machine = st.selectbox("Select Target Machine:", options=machine_options, label_visibility="collapsed")
st.write("")

if not archive_df.empty and selected_machine != "No telemetry found":
    target_bot = selected_machine.split(" (")[0]
    target_os = selected_machine.split(" (")[1].replace(")", "").lower()

    # Determine which columns to show based on OS
    if "windows" in target_os:
        display_columns = ["Time", "Source", "User", "Domain", "Logon ID", "Message"]
    elif "linux" in target_os:
        display_columns = ["Time", "Source", "User", "RHost", "Message"]
    else:
        display_columns = ["Time", "Source", "User", "Message"]

    filtered_logs = archive_df[archive_df["Doombot"] == target_bot][display_columns]
    recent_logs = filtered_logs.tail(10).iloc[::-1]

    html_table = recent_logs.to_html(index=False, classes="custom-table")
    st.markdown(html_table, unsafe_allow_html=True)
else:
    st.info("No logs archived yet.")
st.write("")
st.write("")


# Analytics Section
col_radar, col_timeseries = st.columns([1, 1])
with col_radar:
    radar_categories = ['System', 'Application', 'Disclosure', 'Network', 'Authentication']
    cats = {c: 0 for c in radar_categories}
    if not archive_df.empty:
        for raw in archive_df["Raw Log"]:
            raw_lower = raw.lower()
            if any(x in raw_lower for x in ["password", "fail", "invalid", "login", "4624", "4625"]): cats['Authentication'] += 1
            elif any(x in raw_lower for x in ["ip", "tcp", "http", "port", "network"]): cats['Network'] += 1
            elif any(x in raw_lower for x in ["error", "kernel", "system"]): cats['System'] += 1
            elif any(x in raw_lower for x in ["select ", "union ", "inject"]): cats['Application'] += 1
            else: cats['Disclosure'] += 1
    else:
        cats = {c: 1 for c in radar_categories} 
        
    radar_values = [cats[c] for c in radar_categories]
    radar_fig = go.Figure(data=go.Scatterpolar(r=radar_values, theta=radar_categories, fill='toself', fillcolor="#94a3b8", line=dict(color='#94a3b8', width=2), marker=dict(size=5, color='#cbd5e1')))
    radar_fig.update_layout(polar=dict(bgcolor="#021c03", gridshape="linear", radialaxis=dict(visible=False), angularaxis=dict(linecolor="#9FA9B2", color="#9FA9B2")), showlegend=False, height=280, margin=dict(t=20, b=20, l=40, r=40), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(radar_fig, use_container_width=True, key="archive_radar_chart")
    
with col_timeseries:
    if not archive_df.empty:
        time_data = archive_df.groupby("Time").size().reset_index(name="Events")
        time_data = time_data.sort_values("Time")
    else:
        time_data = pd.DataFrame({"Time": ["00:00"], "Events": [0]})
    
    line_fig = px.line(time_data, x="Time", y="Events", markers=True)
    line_fig.update_traces(line_color="#94a3b8", line_shape="spline")
    line_fig.update_layout(height=280, margin=dict(t=20, b=20, l=20, r=20), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#9FA9B2"), xaxis=dict(title="", showgrid=False), yaxis=dict(title="", showgrid=True, gridcolor="#334155"))
    st.plotly_chart(line_fig, use_container_width=True, key="archive_timeline_chart")
