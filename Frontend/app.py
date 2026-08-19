# Since this is at intial stage, the data are hardcoded right now. Database and Node-RED are yet to be set up.

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os

# Page Setup
st.set_page_config(page_title="D.O.O.M. SIEM", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<style>
    /* This is the theme of the webpage */
    .stApp {
    background-color: #011f02; 
    color: white;
    }
    
    h1, h2, h3, h4 {
    color: #f8fafc; 
    font-weight: 600;
    }
    
    hr {
        border-color: #334155; 
        margin: 24px 0;
    }
    
    .boris-banner {
        background-color: #001a02;
        padding: 24px;
        border-radius: 12px;
        border: 1px solid #334155;
        margin-top: 16px;
    }

    /* This is for table */
    .custom-table {
        width: 100%;
        border-collapse: collapse;
        font-family: sans-serif;
    }
    .custom-table th {
        background-color: #001a02 ;
        color: #94a3b8;
        border: none;
        border-bottom: 1px solid #334155;
        padding: 12px 16px;
        text-align: left;
        font-weight: 600;
    }
    .custom-table td {
        background-color: #011f02
        color: white;
        border: none; 
        border-bottom: 1px solid #1a301b;
        padding: 12px 16px;
    }
</style>
""", unsafe_allow_html=True)

# Sample datasets, I will replace this later with real data
fleet_data = pd.DataFrame([
    {"Doombot": "doombot1", "Machine Name": "<machine name>", "Operating System": "Windows", "IP Address": "192.168.10.1", "Alerts": "None", "Status": "active", "high": 0, "medium": 0, "low": 0},
    {"Doombot": "doombot2", "Machine Name": "<machine name>", "Operating System": "Linux", "IP Address": "192.168.10.2", "Alerts": "1 High", "Status": "inactive", "high": 1, "medium": 0, "low": 0},
    {"Doombot": "doombot3", "Machine Name": "<machine name>", "Operating System": "Windows", "IP Address": "192.168.10.3", "Alerts": "2 Medium", "Status": "inactive", "high": 0, "medium": 2, "low": 1}
])

# Threat Triage Alerts
alerts_data = [
    {
        "alert_name": "<alert name>",
        "machine": "<machine name>",
        "severity": "HIGH",
        "cve_id": "<related cve id>",
        "description": "<AI Analysis of the vulnerability correlating to the machine and the OS.>",
        "cvss": 7, "epss": "10%", "vpr": 6,
        "mitigation": "<AI Analysis of the incident response of the vulnerability.>"
    },
    {
        "alert_name": "<alert name>",
        "machine": "<machine name>",
        "severity": "LOW",
        "cve_id": "<related cve id>",
        "description": "<AI Analysis of the vulnerability correlating to the machine and the OS.>",
        "cvss": 3, "epss": "2%", "vpr": 2,
        "mitigation": "<AI Analysis of the incident response of the vulnerability.>"
    },
    {
        "alert_name": "<alert name>",
        "machine": "<machine name>",
        "severity": "MEDIUM",
        "cve_id": "<related cve id>",
        "description": "<AI Analysis of the vulnerability correlating to the machine and the OS.>",
        "cvss": 5, "epss": "5%", "vpr": 4,
        "mitigation": "<AI Analysis of the incident response of the vulnerability.>"
    }
]

# Windows Sysmon Archive Logs
windows_logs = pd.DataFrame([
    {"Timestamp": "<timestamp>", "Event ID": "<event_id>", "Process ID": "<process_id>", "User": "<user>", "Image": "<image>", "Parent Image": "<parent_image>", "Hashes": "<hash>"},
    {"Timestamp": "<timestamp>", "Event ID": "<event_id>", "Process ID": "<process_id>", "User": "<user>", "Image": "<image>", "Parent Image": "<parent_image>", "Hashes": "<hash>"},
    {"Timestamp": "<timestamp>", "Event ID": "<event_id>", "Process ID": "<process_id>", "User": "<user>", "Image": "<image>", "Parent Image": "<parent_image>", "Hashes": "<hash>"}
])

# Linux Syslog Archive Logs
linux_logs = pd.DataFrame([
    {"Timestamp": "<timestamp>", "Hostname": "<hostname>", "Process": "<process_name>", "Description": "<description>"},
    {"Timestamp": "<timestamp>", "Hostname": "<hostname>", "Process": "<process_name>", "Description": "<description>"},
    {"Timestamp": "<timestamp>", "Hostname": "<hostname>", "Process": "<process_name>", "Description": "<description>"}
])


# Boris AI Analysis
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
col_logo, col_title = st.columns([1, 10])

with col_logo:
    if os.path.exists("Logo.png"):
        st.image("Logo.png", width=90)
    else:
        st.markdown("```\n[ LOGO ]\n```")

with col_title:
    st.markdown("# D . O . O . M")

st.write("")

# Doombot Assets
st.subheader("Doombot Assets")

table_col, status_col = st.columns([3, 1])

with table_col:
    display_cols = ["Doombot", "Machine Name", "Operating System", "IP Address", "Alerts", "Status"]
    # Replaced st.dataframe with HTML injection mapped to our CSS class
    st.markdown(fleet_data[display_cols].to_html(index=False, classes="custom-table"), unsafe_allow_html=True)

with status_col:
    status_counts = fleet_data["Status"].value_counts().reset_index()
    status_counts.columns = ["Status", "Count"]
    
    fig_status = px.pie(
        status_counts,
        names="Status",
        values="Count",
        hole=0.6,
        color="Status",
        color_discrete_map={"active": "#0C8E5C", "inactive": "#8E1D0C"}
    )
    fig_status.update_layout(
        margin=dict(t=0, b=0, l=0, r=0),
        height=180,
        showlegend=True,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#cbd5e1")
    )
    st.plotly_chart(fig_status, use_container_width=True, key="status_donut")

# Machine Donut Charts for alerts
st.subheader("Alerts")
machine_cols = st.columns(len(fleet_data))

for idx, row in fleet_data.iterrows():
    with machine_cols[idx]:
        sev_df = pd.DataFrame({
            "Severity": ["high", "medium", "low"],
            "Count": [row["high"], row["medium"], row["low"]]
        })
        
        if sev_df["Count"].sum() == 0:
            sev_df = pd.DataFrame({"Severity": ["none"], "Count": [1]})
            color_map = {"none": "#cbd5e1"}
        else:
            color_map = {"high": "#00643D", "medium": "#FFEC83", "low": "#9FA9B2"}

        fig_machine = px.pie(
            sev_df,
            names="Severity",
            values="Count",
            hole=0.6,
            color="Severity",
            color_discrete_map=color_map
        )
        fig_machine.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            height=180,
            showlegend=True,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#cbd5e1")
        )
        st.plotly_chart(fig_machine, use_container_width=True, key=f"alert_donut_{row['Doombot']}_{idx}")
        st.markdown(f"<p style='text-align: center; font-weight: bold; color: #94a3b8;'>{row['Machine Name']}</p>", unsafe_allow_html=True)

st.divider()

# Threat Triage
st.subheader("Threat Triage")

# Table Header
h_col1, h_col2, h_col3, h_col4 = st.columns([3, 3, 2, 1.5])
h_col1.markdown("**Alert**")
h_col2.markdown("**Machine**")
h_col3.markdown("**Severity**")
h_col4.markdown("**View Details**")
st.markdown("<hr style='margin: 4px 0;'/>", unsafe_allow_html=True)

# Table Rows
for idx, alert in enumerate(alerts_data):
    c1, c2, c3, c4 = st.columns([3, 3, 2, 1.5])
    c1.write(alert["alert_name"])
    c2.write(alert["machine"])
    c3.write(alert["severity"])
    if c4.button("● ● ●", key=f"btn_details_{idx}"):
        boris_popup(alert)
    st.markdown("<hr style='margin: 4px 0;'/>", unsafe_allow_html=True)

st.markdown("""
<div class="boris-banner">
    <h3>Boris Analysis</h3>
    <p>AI Analysis based on alerts. AI will evaluate the alerts, severity and incident response as well as mitigation.</p>
</div>
""", unsafe_allow_html=True)

st.divider()

# Doombots Archive
st.subheader("Doombots Archive")

selected_machine = st.selectbox(
    "Select Target Machine:",
    options=["<machine name> (Windows)", "<machine name> (Linux)"],
    label_visibility="collapsed"
)

st.write("")

# Dynamic Archive Log Grid
# Replaced st.dataframe with HTML injection mapped to our CSS class
if "(Windows)" in selected_machine:
    st.markdown(windows_logs.to_html(index=False, classes="custom-table"), unsafe_allow_html=True)
else:
    st.markdown(linux_logs.to_html(index=False, classes="custom-table"), unsafe_allow_html=True)

st.write("")
st.write("")

# Log Radar
col_radar, col_timeseries = st.columns([1, 1])

with col_radar:
    radar_categories = ['System', 'Application', 'Disclosure', 'Network', 'Authentication']
    radar_values = [4, 2, 1, 3, 5]
    
    radar_fig = go.Figure(data=go.Scatterpolar(
        r=radar_values,
        theta=radar_categories,
        fill='toself',
        fillcolor="#94a3b8",
        line=dict(color='#94a3b8', width=2),
        marker=dict(size=5, color='#cbd5e1')
    ))
    
    radar_fig.update_layout(
        polar=dict(
            bgcolor="#021c03",
            gridshape="linear",
            radialaxis=dict(visible=False),
            angularaxis=dict(linecolor="#9FA9B2", color="#9FA9B2")
        ),
        showlegend=False,
        height=280,
        margin=dict(t=20, b=20, l=40, r=40),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)"
    )
    st.plotly_chart(radar_fig, use_container_width=True, key="archive_radar_chart")
    
# Time Series
with col_timeseries:
    time_data = pd.DataFrame({
        "Time": ["9:00", "9:15", "9:30", "9:45", "10:00", "10:15"],
        "Events": [8, 10, 18, 26, 12, 11]
    })
    
    line_fig = px.line(time_data, x="Time", y="Events", markers=True)
    line_fig.update_traces(line_color="#94a3b8", line_shape="spline")
    line_fig.update_layout(
        height=280,
        margin=dict(t=20, b=20, l=20, r=20),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#9FA9B2"),
        xaxis=dict(title="", showgrid=False),
        yaxis=dict(title="", showgrid=True, gridcolor="#334155", range=[0, 30])
    )
    st.plotly_chart(line_fig, use_container_width=True, key="archive_timeline_chart")
