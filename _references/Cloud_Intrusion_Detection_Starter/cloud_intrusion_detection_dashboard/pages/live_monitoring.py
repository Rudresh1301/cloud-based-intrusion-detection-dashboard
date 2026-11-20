"""
Simulated Live SOC Monitoring Interface.
Demonstrates continuous real-time log streaming, event generation,
host behavioral monitoring, and instant alert triggering.
"""
import time
import random
from datetime import datetime
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from config.settings import (
    COLOR_CARD,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_GREEN,
    COLOR_RED,
    COLOR_ORANGE,
    COLOR_CYAN,
    COLOR_ACCENT,
    COLOR_GRID,
)
from utils.helpers import get_severity_badge_html

# Realistic event pool for live simulation
SIM_IPS = [
    "192.168.1.10", "192.168.1.15", "10.0.0.45", "192.168.1.105",
    "103.21.45.67", "185.220.101.33", "45.77.89.12", "91.203.12.78"
]
SIM_USERS = ["alice", "bob", "charlie", "admin", "root", "guest", "scanner", "unknown"]
SIM_ENDPOINTS = [
    "/login", "/dashboard", "/api/v1/metrics", "/search?q=test",
    "/search?id=1 OR 1=1", "/download?file=../../etc/passwd",
    "/comment?msg=<script>alert(1)</script>", "/admin/config.php",
    "/tools/ping?host=127.0.0.1; whoami"
]

def render_live_monitoring():
    """Renders the real-time simulation monitoring interface."""
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <h2 style="color: {COLOR_TEXT}; margin-bottom: 4px;">📡 Live SOC Telemetry Stream</h2>
                    <p style="color: {COLOR_MUTED}; font-size: 0.9rem;">
                        Real-time log ingestion simulator demonstrating continuous detection of active threats.
                    </p>
                </div>
                <div style="background: rgba(255,176,32,0.12); border: 1px solid rgba(255,176,32,0.4); padding: 5px 14px; border-radius: 20px; color: {COLOR_ORANGE}; font-size: 0.8rem; font-weight: 700;">
                    ⚠️ SIMULATION DEMO MODE
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    if "live_running" not in st.session_state:
        st.session_state.live_running = False
    if "live_events" not in st.session_state:
        st.session_state.live_events = []
    if "live_threats" not in st.session_state:
        st.session_state.live_threats = 0

    # Controls
    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([1, 1, 2])
    with ctrl_col1:
        if st.session_state.live_running:
            if st.button("⏹️ Stop Telemetry Stream", type="secondary", use_container_width=True):
                st.session_state.live_running = False
                st.rerun()
        else:
            if st.button("▶️ Start Live Stream", type="primary", use_container_width=True):
                st.session_state.live_running = True
                st.rerun()

    with ctrl_col2:
        if st.button("🔄 Clear Stream Buffer", use_container_width=True):
            st.session_state.live_events = []
            st.session_state.live_threats = 0
            st.rerun()

    with ctrl_col3:
        status_text = "🟢 STREAM ACTIVE • INGESTING" if st.session_state.live_running else "⚪ STREAM PAUSED"
        status_color = COLOR_GREEN if st.session_state.live_running else COLOR_MUTED
        st.markdown(
            f"""
            <div style="text-align: right; padding-top: 8px; font-weight: 700; font-size: 0.85rem; color: {status_color};">
                {status_text}
            </div>
            """,
            unsafe_allow_html=True
        )

    st.write("")

    # Live Stat Counters
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Ingested Stream Events", f"{len(st.session_state.live_events):,}")
    m2.metric("Threats Flagged", f"{st.session_state.live_threats:,}")
    m3.metric("Telemetry Rate", "1.2 evt/sec" if st.session_state.live_running else "0.0 evt/sec")
    m4.metric("Stream Status", "Normal" if st.session_state.live_threats < 5 else "High Alert")

    st.write("")

    # If stream is running, generate 1-3 new events
    if st.session_state.live_running:
        new_events = []
        for _ in range(random.randint(1, 2)):
            ip = random.choice(SIM_IPS)
            user = random.choice(SIM_USERS)
            ep = random.choice(SIM_ENDPOINTS)
            now_str = datetime.now().strftime("%H:%M:%S")

            is_threat = False
            threat_type = "Normal Request"
            sev = "Low"

            if "UNION" in ep or "OR 1=1" in ep:
                is_threat = True
                threat_type = "SQL Injection"
                sev = "Critical"
                status = "blocked"
            elif "script" in ep:
                is_threat = True
                threat_type = "XSS Payload"
                sev = "High"
                status = "blocked"
            elif "etc/passwd" in ep or "whoami" in ep:
                is_threat = True
                threat_type = "Command / Traversal"
                sev = "Critical"
                status = "blocked"
            elif ip == "192.168.1.105":
                is_threat = True
                threat_type = "Brute Force Pattern"
                sev = "High"
                status = "failed"
            else:
                status = random.choice(["success", "success", "success", "failed"])

            evt = {
                "time": now_str,
                "ip": ip,
                "user": user,
                "endpoint": ep,
                "status": status,
                "is_threat": is_threat,
                "threat_type": threat_type,
                "severity": sev
            }
            new_events.append(evt)
            if is_threat:
                st.session_state.live_threats += 1

        # Keep last 50 events in buffer
        st.session_state.live_events = (new_events + st.session_state.live_events)[:40]

    # Display Live Feed
    col_feed, col_viz = st.columns([1.6, 1])

    with col_feed:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 18px;">
                <div style="font-weight: 700; color: {COLOR_TEXT}; font-size: 0.95rem; margin-bottom: 12px;">
                    ⚡ Live Ingestion Feed (Latest 40 Packets)
                </div>
            """,
            unsafe_allow_html=True
        )

        if st.session_state.live_events:
            for item in st.session_state.live_events[:12]:
                border_color = COLOR_RED if item["is_threat"] else "rgba(22, 72, 121, 0.4)"
                bg_color = "rgba(255, 69, 96, 0.08)" if item["is_threat"] else "transparent"
                badge = get_severity_badge_html(item["severity"]) if item["is_threat"] else ""

                st.markdown(
                    f"""
                    <div style="background: {bg_color}; border-left: 3px solid {border_color}; padding: 8px 12px; margin-bottom: 6px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span style="font-family: monospace; color: {COLOR_MUTED}; font-size: 0.78rem;">[{item['time']}]</span>
                            <span style="font-family: monospace; color: {COLOR_TEXT}; font-weight: bold; font-size: 0.85rem; margin-left: 8px;">{item['ip']}</span>
                            <span style="color: {COLOR_MUTED}; font-size: 0.8rem; margin-left: 6px;">→ {item['endpoint']}</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span style="font-size: 0.75rem; color: {'#00D68F' if item['status'] == 'success' else '#FF4560'};">{item['status'].upper()}</span>
                            {badge}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.info("Stream buffer empty. Click 'Start Live Stream' above to begin simulated telemetry.")

        st.markdown("</div>", unsafe_allow_html=True)

    with col_viz:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 18px;">
                <div style="font-weight: 700; color: {COLOR_TEXT}; font-size: 0.95rem; margin-bottom: 12px;">
                    📈 Real-time Threat Gauge
                </div>
            """,
            unsafe_allow_html=True
        )
        # Gauge chart
        tot = max(1, len(st.session_state.live_events))
        pct = min(100, int((st.session_state.live_threats / tot) * 100))

        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=pct,
            title={'text': "Live Threat Density (%)", 'font': {'color': COLOR_TEXT, 'size': 12}},
            number={'suffix': "%", 'font': {'color': COLOR_TEXT, 'size': 24}},
            gauge={
                'axis': {'range': [0, 100], 'tickcolor': COLOR_MUTED},
                'bar': {'color': COLOR_RED if pct > 30 else COLOR_ACCENT},
                'bgcolor': "rgba(0,0,0,0)",
                'borderwidth': 1,
                'bordercolor': "#164879",
                'steps': [
                    {'range': [0, 20], 'color': "rgba(0,214,143,0.15)"},
                    {'range': [20, 50], 'color': "rgba(255,176,32,0.15)"},
                    {'range': [50, 100], 'color': "rgba(255,69,96,0.2)"}
                ]
            }
        ))
        fig_gauge.update_layout(height=240, margin=dict(l=15, r=15, t=20, b=10), paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_gauge, use_container_width=True, config={"displayModeBar": False})

        st.markdown("</div>", unsafe_allow_html=True)

    # Auto refresh loop if running
    if st.session_state.live_running:
        time.sleep(1.2)
        st.rerun()
