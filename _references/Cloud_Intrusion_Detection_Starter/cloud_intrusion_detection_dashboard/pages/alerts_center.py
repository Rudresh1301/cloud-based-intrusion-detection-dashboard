"""
SOC Alerts Management and Triage Center.
Provides incident lifecycle tracking: New -> Investigating -> Resolved / False Positive.
Buttons actively mutate database state and session store.
"""
import streamlit as st
import pandas as pd
from database.local_db import LocalDatabase, get_local_db
from config.firebase_config import is_firebase_available
from config.settings import (
    COLOR_CARD,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_ACCENT,
    COLOR_ORANGE,
    COLOR_GREEN,
    COLOR_RED,
    ALERT_STATUSES,
)
from utils.helpers import get_severity_badge_html, get_status_badge_html

def render_alerts_center(analysis_results: dict):
    """Renders the interactive alert triage and workflow center."""
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h2 style="color: {COLOR_TEXT}; margin-bottom: 4px;">🚨 Security Incident & Alerts Center</h2>
            <p style="color: {COLOR_MUTED}; font-size: 0.9rem;">
                Triage incoming threat detections, assign investigation states, and manage false positive resolutions.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    alerts_df = analysis_results.get("rule_alerts", pd.DataFrame()) if analysis_results else pd.DataFrame()

    if alerts_df.empty:
        st.success("No active security alerts pending triage.")
        return

    # Initialize Local DB for persistent state changes (cached singleton)
    local_db = get_local_db()

    # Sync local DB alerts if not yet populated
    if "db_synced" not in st.session_state:
        local_db.save_alerts(alerts_df)
        st.session_state.db_synced = True

    # Read current state of alerts from DB
    current_alerts = local_db.get_alerts()
    if not current_alerts:
        local_db.save_alerts(alerts_df)
        current_alerts = local_db.get_alerts()

    curr_df = pd.DataFrame(current_alerts) if current_alerts else alerts_df.copy()

    # ── Status Count Cards ───────────────────────────────────────
    counts = local_db.get_alert_counts()
    c_new, c_inv, c_res, c_fp = st.columns(4)
    c_new.metric("New Unassigned", f"{counts.get('New', 0):,}")
    c_inv.metric("Under Investigation", f"{counts.get('Investigating', 0):,}")
    c_res.metric("Resolved / Closed", f"{counts.get('Resolved', 0):,}")
    c_fp.metric("False Positives", f"{counts.get('False Positive', 0):,}")

    st.write("")

    # Filters
    f_col1, f_col2 = st.columns(2)
    with f_col1:
        status_filter = st.multiselect(
            "Filter by Incident Status",
            options=ALERT_STATUSES,
            default=["New", "Investigating"]
        )
    with f_col2:
        sev_filter = st.multiselect(
            "Filter by Severity",
            options=["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"]
        )

    # Filtered alert list
    display_alerts = [
        a for a in current_alerts
        if (not status_filter or a.get("status", "New") in status_filter) and
           (not sev_filter or a.get("severity", "Medium") in sev_filter)
    ]

    st.markdown(f"#### Active Incidents ({len(display_alerts):,} Listed)")

    if not display_alerts:
        st.info("No alerts match the chosen status and severity filters.")
        return

    # Render each alert card with working state change buttons
    for alert in display_alerts[:15]:
        aid = alert.get("id", alert.get("alert_id"))
        status = alert.get("status", "New")
        sev = alert.get("severity", "Medium")
        atype = alert.get("alert_type", "Threat")
        ip = alert.get("source_ip", "Unknown")
        ts = alert.get("timestamp", "N/A")
        evidence = alert.get("evidence", "")

        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 10px; padding: 14px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        {get_severity_badge_html(sev)}
                        <span style="font-weight: 700; color: {COLOR_TEXT}; font-size: 0.92rem;">{atype}</span>
                        <span style="font-family: monospace; color: {COLOR_ACCENT}; font-size: 0.85rem;">from {ip}</span>
                    </div>
                    <div>
                        {get_status_badge_html(status)}
                    </div>
                </div>
                <div style="font-size: 0.82rem; color: {COLOR_MUTED}; margin-bottom: 10px;">
                    Timestamp: <b>{ts}</b> • Evidence: <code>{evidence}</code>
                </div>
            """,
            unsafe_allow_html=True
        )

        # Working action buttons
        b1, b2, b3, b4 = st.columns([1, 1, 1, 2])
        with b1:
            if status != "Investigating":
                if st.button("🔍 Investigate", key=f"inv_{aid}", use_container_width=True):
                    local_db.update_alert_status(aid, "Investigating")
                    st.success(f"Incident {aid[:8]} marked Investigating")
                    st.rerun()
        with b2:
            if status != "Resolved":
                if st.button("✅ Resolve", key=f"res_{aid}", use_container_width=True):
                    local_db.update_alert_status(aid, "Resolved")
                    st.success(f"Incident {aid[:8]} marked Resolved")
                    st.rerun()
        with b3:
            if status != "False Positive":
                if st.button("❌ False Pos", key=f"fp_{aid}", use_container_width=True):
                    local_db.update_alert_status(aid, "False Positive")
                    st.warning(f"Incident {aid[:8]} classified as False Positive")
                    st.rerun()
        with b4:
            if status in ["Resolved", "False Positive"]:
                if st.button("🔄 Reopen Incident", key=f"reopen_{aid}", use_container_width=True):
                    local_db.update_alert_status(aid, "New")
                    st.info(f"Incident {aid[:8]} reopened")
                    st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)
