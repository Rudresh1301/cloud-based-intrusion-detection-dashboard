"""
IP Host Intelligence and Profiling Console.
Allows SOC analysts to perform deep forensic reconnaissance on any IP host recorded in logs.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
from core.ip_analyzer import IPAnalyzer
from config.settings import (
    COLOR_CARD,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_ELECTRIC,
    COLOR_GRID,
)
from utils.helpers import get_severity_badge_html

@st.cache_data
def get_ip_timeline_fig(ip_logs: pd.DataFrame):
    """Generates and caches host timeline bar chart."""
    if ip_logs is None or ip_logs.empty or "timestamp_dt" not in ip_logs.columns:
        return None
    try:
        ts_summary = ip_logs.set_index("timestamp_dt").resample("h").size().reset_index(name="requests")
        fig = px.bar(
            ts_summary,
            x="timestamp_dt",
            y="requests",
            labels={"timestamp_dt": "Hour", "requests": "Events"},
            color_discrete_sequence=[COLOR_ELECTRIC]
        )
        fig.update_layout(
            height=240,
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color=COLOR_MUTED, size=10),
            xaxis=dict(gridcolor=COLOR_GRID),
            yaxis=dict(gridcolor=COLOR_GRID)
        )
        return fig
    except Exception:
        return None

def render_ip_intelligence(analysis_results: dict):
    """Renders the IP host intelligence reconnaissance interface."""
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h2 style="color: {COLOR_TEXT}; margin-bottom: 4px;">🌐 IP Intelligence & Host Profiling</h2>
            <p style="color: {COLOR_MUTED}; font-size: 0.9rem;">
                Perform comprehensive forensic profiling, behavioral risk scoring, and threat correlation on host IPs.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    enriched_logs = analysis_results.get("enriched_logs", pd.DataFrame()) if analysis_results else pd.DataFrame()
    alerts_df = analysis_results.get("rule_alerts", pd.DataFrame()) if analysis_results else pd.DataFrame()

    if enriched_logs.empty:
        st.warning("No log data available to analyze IP intelligence.")
        return

    analyzer = IPAnalyzer()
    unique_ips = sorted(list(enriched_logs["source_ip"].astype(str).unique()))
    suspicious_ips = sorted(list(alerts_df["source_ip"].astype(str).unique())) if not alerts_df.empty else []

    # IP Search & Quick Select Bar
    s_col1, s_col2 = st.columns([1.5, 1])
    with s_col1:
        default_idx = unique_ips.index(suspicious_ips[0]) if (suspicious_ips and suspicious_ips[0] in unique_ips) else 0
        target_ip = st.selectbox("Select or Type Host IP to Investigate", options=unique_ips, index=default_idx)
    with s_col2:
        st.markdown("<div style='padding-top: 28px;'></div>", unsafe_allow_html=True)
        if suspicious_ips:
            st.caption(f"⚠️ Known Flagged Attackers: {', '.join(suspicious_ips[:4])}")

    st.write("")

    # Detailed Dossier for selected IP
    dossier = analyzer.analyze_ip(target_ip, enriched_logs, alerts_df)

    if not dossier.get("found", False):
        st.info(dossier.get("message", "IP not found."))
        return

    # Overview Cards
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Network Zone", dossier["classification"])
    c2.metric("Total Events Recorded", f"{dossier['total_events']:,}")
    c3.metric("Associated Alerts", f"{dossier['alert_count']:,}")
    c4.metric("Failure Ratio", f"{dossier['failed_ratio']*100:.0f}%")

    st.write("")

    # Risk Assessment Banner
    r_color = dossier["risk_color"]
    st.markdown(
        f"""
        <div style="background: {COLOR_CARD}; border-left: 4px solid {r_color}; border-radius: 10px; padding: 16px; display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
            <div>
                <span style="font-size: 0.8rem; color: {COLOR_MUTED}; text-transform: uppercase;">Host Behavioral Threat Rating</span>
                <div style="font-size: 1.4rem; font-weight: 800; color: {r_color};">{dossier['risk_level'].upper()} (Risk Index: {dossier['risk_score']}/100)</div>
                <div style="font-size: 0.82rem; color: {COLOR_MUTED}; margin-top: 4px;">
                    First Seen: <b>{dossier['first_seen']}</b> • Last Activity: <b>{dossier['last_seen']}</b>
                </div>
            </div>
            <div style="text-align: right;">
                <span style="background: {r_color}22; color: {r_color}; border: 1px solid {r_color}55; padding: 6px 14px; border-radius: 20px; font-weight: bold; font-size: 0.85rem;">
                    {dossier['risk_level']} Severity Host
                </span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Activity Visualizations
    v_col1, v_col2 = st.columns([1.5, 1])

    with v_col1:
        st.markdown("#### Host Request Timeline")
        ip_logs = dossier.get("logs_df", pd.DataFrame())
        fig = get_ip_timeline_fig(ip_logs)
        if fig is not None:
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No timeline data.")

    with v_col2:
        st.markdown("#### Target Endpoints Hit")
        eps = dossier.get("endpoints", [])
        if eps:
            for ep in eps[:6]:
                st.markdown(f"• <code style='font-size: 0.8rem;'>{ep}</code>", unsafe_allow_html=True)
        else:
            st.caption("No endpoints accessed.")

    # Alerts Triggered by this Host
    st.write("")
    st.markdown("#### Threat Alerts Triggered by this Host")
    host_alerts = dossier.get("alerts_df", pd.DataFrame())
    if not host_alerts.empty:
        for a in host_alerts.itertuples(index=False):
            alert_type = getattr(a, "alert_type", "")
            evidence = getattr(a, "evidence", "")
            severity = getattr(a, "severity", "Low")
            st.markdown(
                f"""
                <div style="background: {COLOR_CARD}; border: 1px solid #164879; padding: 10px 14px; border-radius: 8px; margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="color: {COLOR_TEXT}; font-weight: 600; font-size: 0.88rem;">{alert_type}</span>
                        <span style="color: {COLOR_MUTED}; font-size: 0.78rem; margin-left: 10px;">{evidence}</span>
                    </div>
                    {get_severity_badge_html(severity)}
                </div>
                """,
                unsafe_allow_html=True
            )
    else:
        st.success("No security rule violations or threat alerts triggered by this host.")
