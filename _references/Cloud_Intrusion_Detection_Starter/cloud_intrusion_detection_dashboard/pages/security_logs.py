"""
Searchable and Filterable Security Log Explorer.
Allows SOC analysts to filter, paginate, inspect and export enriched access log records.
"""
import streamlit as st
import pandas as pd
from config.settings import (
    COLOR_CARD,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_ACCENT,
    COLOR_GREEN,
    COLOR_RED,
    ITEMS_PER_PAGE,
)

def render_security_logs(analysis_results: dict):
    """Renders the comprehensive log explorer."""
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h2 style="color: {COLOR_TEXT}; margin-bottom: 4px;">📋 Security Log Explorer & Audit Records</h2>
            <p style="color: {COLOR_MUTED}; font-size: 0.9rem;">
                Browse, search, correlate, and inspect raw & enriched security event logs across all monitored endpoints.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    enriched_logs = analysis_results.get("enriched_logs", pd.DataFrame()) if analysis_results else pd.DataFrame()
    alerts_df = analysis_results.get("rule_alerts", pd.DataFrame()) if analysis_results else pd.DataFrame()

    if enriched_logs.empty:
        st.warning("No log data available to explore. Please load a dataset first.")
        return

    # Correlate logs with threat status using fast vectorized isin
    flagged_ips = set(alerts_df["source_ip"].astype(str).unique()) if not alerts_df.empty else set()
    display_df = enriched_logs.copy()
    import numpy as np
    display_df["Verdict"] = np.where(display_df["source_ip"].astype(str).isin(flagged_ips), "🚨 Suspicious", "✅ Normal")

    # ── Search & Filter Panel ────────────────────────────────────
    st.markdown(
        f"""
        <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 16px; margin-bottom: 15px;">
        """,
        unsafe_allow_html=True
    )

    f1, f2, f3, f4 = st.columns([1.5, 1, 1, 1])
    with f1:
        search_kw = st.text_input("Search Logs (IP, User, Endpoint, Event)", placeholder="e.g. login, /admin, 103.21...")
    with f2:
        all_statuses = ["All"] + sorted(list(display_df["status"].astype(str).unique()))
        selected_status = st.selectbox("Status Filter", options=all_statuses)
    with f3:
        all_verdicts = ["All", "🚨 Suspicious", "✅ Normal"]
        selected_verdict = st.selectbox("Verdict", options=all_verdicts)
    with f4:
        all_endpoints = ["All"] + sorted(list(display_df["endpoint_category"].dropna().unique()))
        selected_cat = st.selectbox("Endpoint Category", options=all_endpoints)

    st.markdown("</div>", unsafe_allow_html=True)

    # Fast Vectorized Filtering
    filtered = display_df
    if search_kw.strip():
        kw = search_kw.strip().lower()
        search_blob = (display_df["source_ip"].astype(str) + " " +
                       display_df["username"].astype(str) + " " +
                       display_df["endpoint"].astype(str) + " " +
                       display_df["event_type"].astype(str)).str.lower()
        filtered = filtered[search_blob.str.contains(kw, na=False)]
    if selected_status != "All":
        filtered = filtered[filtered["status"] == selected_status]
    if selected_verdict != "All":
        filtered = filtered[filtered["Verdict"] == selected_verdict]
    if selected_cat != "All":
        filtered = filtered[filtered["endpoint_category"] == selected_cat]

    # Quick count
    st.markdown(f"**Showing {len(filtered):,} matching records** (Total: {len(display_df):,})")

    # ── Pagination Controls ──────────────────────────────────────
    if "log_page" not in st.session_state:
        st.session_state.log_page = 0

    total_pages = max(1, (len(filtered) - 1) // ITEMS_PER_PAGE + 1)
    if st.session_state.log_page >= total_pages:
        st.session_state.log_page = max(0, total_pages - 1)

    start_idx = st.session_state.log_page * ITEMS_PER_PAGE
    end_idx = start_idx + ITEMS_PER_PAGE
    page_data = filtered.iloc[start_idx:end_idx]

    # Display columns
    show_cols = ["timestamp", "source_ip", "username", "event_type", "status", "endpoint", "Verdict"]
    st.dataframe(
        page_data[show_cols],
        use_container_width=True,
        hide_index=True
    )

    # Pagination navigation
    p_col1, p_col2, p_col3 = st.columns([1, 2, 1])
    with p_col1:
        if st.button("⬅️ Previous", disabled=(st.session_state.log_page == 0), use_container_width=True):
            st.session_state.log_page = max(0, st.session_state.log_page - 1)
            st.rerun()
    with p_col2:
        st.markdown(
            f"""
            <div style="text-align: center; padding-top: 8px; color: {COLOR_MUTED}; font-size: 0.85rem;">
                Page <b>{st.session_state.log_page + 1}</b> of <b>{total_pages}</b>
            </div>
            """,
            unsafe_allow_html=True
        )
    with p_col3:
        if st.button("Next ➡️", disabled=(st.session_state.log_page >= total_pages - 1), use_container_width=True):
            st.session_state.log_page += 1
            st.rerun()

    # Export to CSV
    st.write("")
    st.download_button(
        label="📥 Export Current Filtered Logs to CSV",
        data=filtered[show_cols].to_csv(index=False).encode("utf-8"),
        file_name="security_access_logs_filtered.csv",
        mime="text/csv"
    )
