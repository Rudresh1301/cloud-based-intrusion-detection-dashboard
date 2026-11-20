"""
Log Ingestion and Processing Interface.
Allows users to upload custom CSV or TXT server/network logs, performs thorough validation,
displays data diagnostics, avoids duplicate file processing, and triggers pipeline re-analysis.
"""
import io
import hashlib
import streamlit as st
import pandas as pd
from pathlib import Path
from utils.validators import validate_csv_upload, clean_dataframe
from config.settings import (
    COLOR_CARD,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_ACCENT,
    COLOR_GREEN,
    COLOR_RED,
    COLOR_ORANGE,
    REQUIRED_COLUMNS,
)

SAMPLE_FILE = Path(__file__).parent.parent / "data" / "sample_logs.csv"

@st.cache_data(show_spinner=False)
def parse_and_validate_file_cached(file_bytes: bytes, file_name: str) -> tuple[pd.DataFrame | None, dict, list, list]:
    """
    Cached parser and validator keyed by the file's raw bytes to avoid duplicate processing.
    """
    try:
        if file_name.endswith(".csv"):
            try:
                raw_df = pd.read_csv(io.BytesIO(file_bytes))
            except Exception:
                raw_df = pd.read_csv(io.BytesIO(file_bytes), on_bad_lines='skip')
        else:
            content = file_bytes.decode("utf-8", errors="ignore")
            try:
                raw_df = pd.read_csv(io.StringIO(content))
            except Exception:
                raw_df = pd.read_csv(io.StringIO(content), on_bad_lines='skip')

        val_res = validate_csv_upload(raw_df)
        cleaned = clean_dataframe(raw_df) if val_res["valid"] else None
        return cleaned, val_res["stats"], val_res["errors"], val_res["warnings"]
    except Exception as e:
        return None, {}, [f"Parsing failed: {str(e)}"], []

def render_upload_logs():
    """Renders the log file upload and validation console."""
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h2 style="color: {COLOR_TEXT}; margin-bottom: 4px;">📤 Log Ingestion & Ingestion Engine</h2>
            <p style="color: {COLOR_MUTED}; font-size: 0.9rem;">
                Upload enterprise application or network proxy access logs for multi-vector threat inspection.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    col_up, col_info = st.columns([1.6, 1])

    with col_up:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 14px; padding: 22px;">
                <div style="font-size: 1rem; font-weight: 700; color: {COLOR_TEXT}; margin-bottom: 8px;">Upload Log File</div>
                <div style="font-size: 0.82rem; color: {COLOR_MUTED}; margin-bottom: 15px;">
                    Supported formats: <b>CSV</b> or formatted <b>TXT</b> (Apache/Nginx or Delimited)
                </div>
            """,
            unsafe_allow_html=True
        )

        uploaded_file = st.file_uploader(
            "Choose log file",
            type=["csv", "txt"],
            label_visibility="collapsed"
        )

        st.markdown("</div>", unsafe_allow_html=True)

    with col_info:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 14px; padding: 22px;">
                <div style="font-size: 1rem; font-weight: 700; color: {COLOR_TEXT}; margin-bottom: 8px;">Schema Requirements</div>
                <div style="font-size: 0.8rem; color: {COLOR_MUTED}; line-height: 1.6;">
                    For CSV ingestion, the file header must include the following mandatory columns:
                </div>
                <div style="margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px;">
                    {" ".join([f"<code style='background: rgba(0,168,255,0.15); color: {COLOR_ACCENT}; padding: 3px 8px; border-radius: 6px; font-size: 0.78rem;'>{c}</code>" for c in REQUIRED_COLUMNS])}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write("")
        if SAMPLE_FILE.exists():
            sample_bytes = SAMPLE_FILE.read_bytes()
            st.download_button(
                label="📥 Download Standard Sample Dataset (150 Rows)",
                data=sample_bytes,
                file_name="sample_logs.csv",
                mime="text/csv",
                use_container_width=True
            )

    # Process Uploaded File with duplicate detection and caching
    if uploaded_file is not None:
        st.write("")
        file_bytes = uploaded_file.getvalue()
        file_hash = hashlib.sha256(file_bytes).hexdigest()

        with st.spinner("Validating and parsing uploaded log data..."):
            cleaned_df, stats, errors, warnings = parse_and_validate_file_cached(file_bytes, uploaded_file.name)

        if stats:
            # Diagnostic metrics
            st.markdown("### 📊 Ingestion Diagnostics")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Raw Records", f"{stats.get('total_rows', 0):,}")
            c2.metric("Valid Syntax Rows", f"{stats.get('valid_rows', 0):,}")
            c3.metric("Duplicate Entries", f"{stats.get('duplicate_rows', 0):,}")
            c4.metric("Invalid IP / Dates", f"{stats.get('invalid_rows', 0) + stats.get('invalid_ips', 0):,}")

        if errors:
            for err in errors:
                st.error(f"❌ Schema Error: {err}")
        elif cleaned_df is not None:
            if warnings:
                with st.expander("⚠️ Ingestion Warnings (Auto-Sanitized)", expanded=False):
                    for w in warnings:
                        st.caption(f"• {w}")

            st.markdown("#### Data Preview (Top 5 Records)")
            st.dataframe(cleaned_df.head(5), use_container_width=True, hide_index=True)

            # Check if this exact file is already the active dataset
            is_already_active = (
                st.session_state.get("active_file_hash") == file_hash and
                len(st.session_state.get("logs", [])) == len(cleaned_df)
            )

            if is_already_active:
                st.info("ℹ️ This dataset is currently active and analyzed across the dashboard.")

            # Primary Action Button
            st.write("")
            col_btn, _ = st.columns([1.2, 2])
            with col_btn:
                btn_label = "🔄 RE-ANALYZE THIS DATASET" if is_already_active else "🚀 ANALYZE UPLOADED LOGS"
                if st.button(btn_label, use_container_width=True, type="primary"):
                    with st.spinner("Executing rule evaluation and ML anomaly scoring..."):
                        st.session_state.logs = cleaned_df
                        st.session_state.active_file_hash = file_hash
                        st.session_state.reanalyze_trigger = True
                    st.success(f"Successfully loaded and analyzed {len(cleaned_df):,} records!")
                    st.rerun()
