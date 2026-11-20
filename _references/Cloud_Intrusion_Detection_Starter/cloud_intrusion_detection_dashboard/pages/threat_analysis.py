"""
Threat Analysis and Investigation Interface.
Provides deep-dive inspection into detected attack signatures, rule triggers,
forensic evidence, payload analysis, and remediation paths.
"""
import streamlit as st
import pandas as pd
from config.settings import (
    COLOR_CARD,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_RED,
    COLOR_ORANGE,
    COLOR_PURPLE,
    COLOR_CYAN,
    COLOR_ACCENT,
)
from utils.helpers import get_severity_badge_html, get_status_badge_html

def render_threat_analysis(analysis_results: dict):
    """Renders the comprehensive threat investigation console."""
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h2 style="color: {COLOR_TEXT}; margin-bottom: 4px;">🎯 Threat Investigation & Forensics</h2>
            <p style="color: {COLOR_MUTED}; font-size: 0.9rem;">
                Inspect detected attack indicators, forensic evidence, and contextual mitigation recommendations.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    alerts_df = analysis_results.get("rule_alerts", pd.DataFrame()) if analysis_results else pd.DataFrame()
    sev_counts = analysis_results.get("severity_counts", {}) if analysis_results else {}

    # ── Severity KPI Cards ───────────────────────────────────────
    c_tot, c_crit, c_high, c_med, c_low = st.columns(5)
    c_tot.metric("Total Threats", f"{len(alerts_df):,}")
    c_crit.metric("Critical", f"{sev_counts.get('Critical', 0):,}")
    c_high.metric("High Severity", f"{sev_counts.get('High', 0):,}")
    c_med.metric("Medium Severity", f"{sev_counts.get('Medium', 0):,}")
    c_low.metric("Low Severity", f"{sev_counts.get('Low', 0):,}")

    st.write("")

    if alerts_df.empty:
        st.success("✅ Clean bill of health. No suspicious activity detected in the current log set.")
        return

    # ── Interactive Filter Controls ──────────────────────────────
    filt_col1, filt_col2, filt_col3 = st.columns([1.2, 1.5, 1.2])

    with filt_col1:
        selected_sevs = st.multiselect(
            "Filter by Severity",
            options=["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"]
        )

    with filt_col2:
        all_types = sorted(list(alerts_df["alert_type"].unique()))
        selected_types = st.multiselect(
            "Filter by Attack Category",
            options=all_types,
            default=all_types
        )

    with filt_col3:
        search_ip = st.text_input("Search Source IP", placeholder="e.g. 103.21.45.67")

    # Apply filters
    filtered_df = alerts_df.copy()
    if selected_sevs:
        filtered_df = filtered_df[filtered_df["severity"].isin(selected_sevs)]
    if selected_types:
        filtered_df = filtered_df[filtered_df["alert_type"].isin(selected_types)]
    if search_ip.strip():
        filtered_df = filtered_df[filtered_df["source_ip"].str.contains(search_ip.strip(), na=False)]

    st.markdown(f"#### Filtered Threats ({len(filtered_df):,} Matches)")

    # ── Detailed Expandable Threat Cards ─────────────────────────
    if filtered_df.empty:
        st.info("No threat alerts match the selected filters.")
    else:
        for idx, row in filtered_df.head(25).iterrows():
            sev_badge = get_severity_badge_html(row["severity"])
            status_badge = get_status_badge_html(row.get("status", "New"))

            with st.expander(f"{row['severity'].upper()} • {row['alert_type']} from {row['source_ip']} ({row['timestamp']})", expanded=(idx < 2)):
                e_c1, e_c2 = st.columns([1.5, 1])

                with e_c1:
                    st.markdown(f"**Target Account / User:** `{row.get('username', 'N/A')}`")
                    st.markdown(f"**Detection Heuristic:** `{row.get('detection_method', 'Rule Engine')}`")
                    st.markdown(f"**Forensic Evidence:**")
                    st.code(str(row.get("evidence", "No evidence recorded")), language="text")

                with e_c2:
                    st.markdown(f"**Current Status:** {status_badge}", unsafe_allow_html=True)
                    st.markdown(f"**Recommended Countermeasure:**")
                    st.info(str(row.get("recommended_action", "Investigate endpoint access logs.")))

    # Export Button
    st.write("")
    st.download_button(
        label="📥 Export Filtered Threats to CSV",
        data=filtered_df.to_csv(index=False).encode("utf-8"),
        file_name="threat_forensics_export.csv",
        mime="text/csv"
    )
