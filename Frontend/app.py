# Since this is at intial stage, the data are hardcoded right now. Database and Node-RED are yet to be set up.

import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import plotly.graph_objects as go
import os


# STREAMLIT PAGE CONFIG & CLEAN WIREFRAME STYLING

st.set_page_config(page_title="D.O.O.M. Command Matrix", layout="wide")

st.markdown("""
<style>
    /* Clean, scannable layout */
    .stApp { background-color: #0e1117; color: #f1f5f9; }
    h1, h2, h3, h4 { color: #f8fafc; font-weight: 600; }
    .stTabs [data-baseweb="tab-list"] { gap: 16px; }
    .stTabs [data-baseweb="tab"] {
        background-color: #1e293b;
        border-radius: 6px;
        padding: 8px 16px;
        color: #94a3b8;
    }
    .stTabs [aria-selected="true"] {
        background-color: #334155 !important;
        color: #38bdf8 !important;
    }
    .card {
        background-color: #1e293b;
        padding: 16px;
        border-radius: 8px;
        border: 1px solid #334155;
    }
    .modal-box {
        background-color: #1e293b;
        border: 1px solid #475569;
        border-radius: 10px;
        padding: 20px;
    }
</style>
""", unsafe_allow_html=True)


# DATABASE INGESTION & SAMPLE FALLBACK GENERATOR

def get_database_connection():
    db_path = "doom_matrix.db" if os.path.exists("doom_matrix.db") else "../database/doom_matrix.db"
    return sqlite3.connect(db_path)

def load_data():
    try:
        conn = get_database_connection()
        df = pd.read_sql_query("SELECT * FROM asset_vulnerabilities", conn)
        conn.close()
        if not df.empty:
            return df
    except Exception:
        pass
    
    # Realistic mock dataset matching wireframe assets if DB is fresh/empty
    mock_data = [
        {"doombot_id": "doombot1", "machine_name": "Latveria-DC01", "ip_address": "192.168.1.10", "os": "Windows", "mac": "00:1A:2B:3C:4D:5E", "status": "active", "package_name": "OpenSSL", "package_version": "1.1.1", "cve_id": "CVE-2022-0778", "cvss_score": 7.5, "epss_score": 0.12, "vpr_score": 6.8, "affected_asset": "Operating System", "mitre_technique": "T1190 - Exploit Public-Facing App", "boris_description": "OpenSSL BN_mod_sqrt infinite loop vulnerability allowing DoS on domain controller.", "boris_mitigation": "Update OpenSSL to version 1.1.1n or newer via Windows update catalog."},
        {"doombot_id": "doombot1", "machine_name": "Latveria-DC01", "ip_address": "192.168.1.10", "os": "Windows", "mac": "00:1A:2B:3C:4D:5E", "status": "active", "package_name": "SMBv1 Service", "package_version": "1.0", "cve_id": "CVE-2017-0144", "cvss_score": 8.1, "epss_score": 0.45, "vpr_score": 8.5, "affected_asset": "Network", "mitre_technique": "T1210 - Exploitation of Remote Services", "boris_description": "SMBv1 remote code execution exposure detected on DC01.", "boris_mitigation": "Disable SMBv1 protocol globally via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false."},
        {"doombot_id": "doombot2", "machine_name": "Web-Prod-Node", "ip_address": "192.168.1.25", "os": "Linux", "mac": "00:1A:2B:3C:4D:5F", "status": "inactive", "package_name": "Apache HTTPD", "package_version": "2.4.49", "cve_id": "CVE-2021-41773", "cvss_score": 9.8, "epss_score": 0.88, "vpr_score": 9.4, "affected_asset": "Application", "mitre_technique": "T1059 - Command and Scripting Interpreter", "boris_description": "Path traversal and remote code execution flaw in Apache 2.4.49 path normalization.", "boris_mitigation": "Upgrade Apache package immediately: apt-get update && apt-get install --only-upgrade apache2."},
        {"doombot_id": "doombot2", "machine_name": "Web-Prod-Node", "ip_address": "192.168.1.25", "os": "Linux", "mac": "00:1A:2B:3C:4D:5F", "status": "inactive", "package_name": "OpenSSH", "package_version": "8.2p1", "cve_id": "CVE-2024-6387", "cvss_score": 8.1, "epss_score": 0.35, "vpr_score": 7.9, "affected_asset": "Configuration", "mitre_technique": "T1078 - Valid Accounts", "boris_description": "RegreSSHion signal handler race condition in OpenSSH server on Linux.", "boris_mitigation": "Update openssh-server package and set LoginGraceTime to 0 in /etc/ssh/sshd_config as interim workaround."},
        {"doombot_id": "doombot3", "machine_name": "Dev-Workstation-03", "ip_address": "192.168.1.45", "os": "Windows", "mac": "00:1A:2B:3C:4D:5G", "status": "inactive", "package_name": "Google Chrome", "package_version": "114.0.5735", "cve_id": "CVE-2023-3079", "cvss_score": 8.8, "epss_score": 0.22, "vpr_score": 7.1, "affected_asset": "Application", "mitre_technique": "T1203 - Exploitation for Client Execution", "boris_description": "Type confusion in V8 JavaScript engine allowing sandbox escape.", "boris_mitigation": "Deploy enterprise Chrome MSI package version 114.0.5735.199 or newer."}
    ]
    return pd.DataFrame(mock_data)

df = load_data()

def get_severity(cvss):
    if cvss >= 9.0: return "high"
    elif cvss >= 7.0: return "high"
    elif cvss >= 4.0: return "medium"
    return "low"

df["severity"] = df["cvss_score"].apply(get_severity)


# POPUP MODAL: BORIS AI INTELLIGENCE

@st.dialog("Boris Vulnerability Assessment")
def boris_assessment_modal(record):
    st.markdown(f"### {record['package_name']}")
    st.markdown(f"`{record['cve_id']}`")
    
    st.markdown("#### **Boris Description**")
    st.info(f"🤖 {record['boris_description']}")
    
    col_cvss, col_epss, col_vpr = st.columns(3)
    with col_cvss:
        st.metric("CVSS Score", f"{record['cvss_score']}")
    with col_epss:
        st.metric("EPSS Score", f"{int(record['epss_score'] * 100)}%")
    with col_vpr:
        st.metric("VPR Score", f"{record['vpr_score']}")
    
    st.markdown("#### **Boris Mitigation**")
    st.success(f"🛡️ {record['boris_mitigation']}")
    
    if st.button("Acknowledge & Close", use_container_width=True):
        st.rerun()


# TAB NAVIGATION MATCHING WIREFRAME VIEWS

tab_fleet, tab_drilldown, tab_risk = st.tabs([
    "🖥️ Doombot Fleet Overview", 
    "🔍 Machine Threat Matrix", 
    "📋 Boris Risk Table"
])


# FLEET OVERVIEW

with tab_fleet:
    logo_col, space_col = st.columns([1, 6])
    with logo_col:
        if os.path.exists("Logo.png"):
            st.image("Logo.png", width=110)
        else:
            st.markdown("```\n[  LOGO  ]\n[ D.O.O.M]\n```")
            
    st.subheader("Doombot Assets")
    
    col_table, col_status_donut = st.columns([3, 1])
    
    assets_summary = df.groupby(["doombot_id", "machine_name", "os", "mac", "status"]).size().reset_index(name="total_vulns")
    
    top_vulns = []
    for _, row in assets_summary.iterrows():
        machine_df = df[df["machine_name"] == row["machine_name"]]
        high_count = len(machine_df[machine_df["severity"] == "high"])
        med_count = len(machine_df[machine_df["severity"] == "medium"])
        if high_count > 0:
            top_vulns.append(f"{high_count} High")
        elif med_count > 0:
            top_vulns.append(f"{med_count} Medium")
        else:
            top_vulns.append("None")
    assets_summary["Top Vulnerability"] = top_vulns

    with col_table:
        display_assets = assets_summary[["doombot_id", "machine_name", "os", "mac", "Top Vulnerability", "status"]]
        display_assets.columns = ["Doombot", "Machine Name", "OS", "MAC Address", "Top Alert", "Status"]
        st.dataframe(display_assets, use_container_width=True, hide_index=True)

    with col_status_donut:
        status_counts = assets_summary["status"].value_counts().reset_index()
        status_counts.columns = ["Status", "Count"]
        
        fig_active = px.pie(
            status_counts, 
            names="Status", 
            values="Count", 
            hole=0.6,
            color="Status",
            color_discrete_map={"active": "#475569", "inactive": "#94a3b8"}
        )
        fig_active.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            height=180,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#cbd5e1"),
            legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.0)
        )
        st.plotly_chart(fig_active, use_container_width=True)

    st.write("")
    st.write("")
    
    distinct_machines = df["machine_name"].unique()
    
    if len(distinct_machines) > 0:
        donut_cols = st.columns(len(distinct_machines))
        for i, machine in enumerate(distinct_machines):
            with donut_cols[i]:
                sub_df = df[df["machine_name"] == machine]
                sev_counts = sub_df["severity"].value_counts().reindex(["high", "medium", "low"], fill_value=0).reset_index()
                sev_counts.columns = ["Severity", "Count"]
                
                fig_sev = px.pie(
                    sev_counts, 
                    names="Severity", 
                    values="Count", 
                    hole=0.6,
                    color="Severity",
                    color_discrete_map={"high": "#334155", "medium": "#64748b", "low": "#cbd5e1"}
                )
                fig_sev.update_layout(
                    margin=dict(t=5, b=5, l=5, r=5),
                    height=180,
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#cbd5e1"),
                    showlegend=(i == len(distinct_machines) - 1)
                )
                st.plotly_chart(fig_sev, use_container_width=True, key=f"donut_{machine}_{i}")
                st.markdown(f"<p style='text-align: center; font-weight: 600; color: #94a3b8;'>{machine}</p>", unsafe_allow_html=True)


# THREAT MATRIX

with tab_drilldown:
    if len(df) > 0:
        selected_machine = st.selectbox(
            "Select Host:", 
            options=df["machine_name"].unique(),
            label_visibility="collapsed"
        )
        
        selected_df = df[df["machine_name"] == selected_machine].reset_index(drop=True)
        
        top_left_col, top_right_col = st.columns([3, 2])
        
        with top_left_col:
            st.subheader("Vulnerability Findings")
            for idx, row in selected_df.iterrows():
                r_col1, r_col2, r_col3, r_col4 = st.columns([2, 2, 4, 1.5])
                r_col1.write(f"**{row['package_name']}**")
                r_col2.write(f"`{row['cve_id']}`")
                r_col3.caption(f"{row['boris_description'][:65]}...")
                if r_col4.button("••• Details", key=f"btn_modal_{idx}"):
                    boris_assessment_modal(row)
                st.markdown("<hr style='margin: 4px 0; border-color: #334155;'/>", unsafe_allow_html=True)
                
        with top_right_col:
            categories = ['Operating System', 'Application', 'Network', 'Configuration', 'Others']
            asset_counts = selected_df['affected_asset'].value_counts().to_dict()
            r_values = [asset_counts.get(cat, 0) + 1 for cat in categories]
            
            radar_fig = go.Figure(data=go.Scatterpolar(
                r=r_values,
                theta=categories,
                fill='toself',
                fillcolor='rgba(148, 163, 184, 0.4)',
                line=dict(color='#94a3b8', width=2),
                marker=dict(size=6, color='#cbd5e1')
            ))
            
            radar_fig.update_layout(
                polar=dict(
                    radialaxis=dict(visible=True, showticklabels=False, linecolor="#475569"),
                    angularaxis=dict(linecolor="#475569", color="#cbd5e1")
                ),
                showlegend=False,
                height=280,
                margin=dict(t=30, b=30, l=40, r=40),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)"
            )
            st.plotly_chart(radar_fig, use_container_width=True)

        st.divider()

        bottom_left_col, bottom_right_col = st.columns([1, 1])
        
        with bottom_left_col:
            st.subheader("Vulnerabilities Count")
            vuln_per_machine = df.groupby("machine_name").size().reset_index(name="Count").sort_values(by="Count", ascending=False)
            
            bar_fig = px.bar(
                vuln_per_machine, 
                x="machine_name", 
                y="Count", 
                color_discrete_sequence=["#94a3b8"]
            )
            bar_fig.update_layout(
                margin=dict(t=10, b=20, l=10, r=10),
                height=250,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#cbd5e1"),
                xaxis=dict(title="", showgrid=False),
                yaxis=dict(title="", showgrid=True, gridcolor="#334155")
            )
            st.plotly_chart(bar_fig, use_container_width=True)
            
        with bottom_right_col:
            st.subheader("MITRE ATT&CK")
            mitre_counts = df["mitre_technique"].value_counts().reset_index()
            mitre_counts.columns = ["Technique", "Count"]
            
            hbar_fig = px.bar(
                mitre_counts, 
                x="Count", 
                y="Technique", 
                orientation='h', 
                color_discrete_sequence=["#94a3b8"]
            )
            hbar_fig.update_layout(
                margin=dict(t=10, b=20, l=10, r=10),
                height=250,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#cbd5e1"),
                xaxis=dict(title="", showgrid=True, gridcolor="#334155"),
                yaxis=dict(title="", showgrid=False, autorange="reversed")
            )
            st.plotly_chart(hbar_fig, use_container_width=True)


# RISK TABLE

with tab_risk:
    st.subheader("Boris Risk Table")
    if len(df) > 0:
        risk_table = df[["cve_id", "package_name", "machine_name", "affected_asset", "cvss_score"]].copy()
        risk_table.columns = ["Risk ID", "Risk", "Machine", "Affected Assets", "Risk Score"]
        
        risk_table["Priority"] = risk_table["Risk Score"].apply(
            lambda s: "Critical" if s >= 9.0 else ("High" if s >= 7.0 else "Medium")
        )
        
        st.dataframe(risk_table, use_container_width=True, hide_index=True)
