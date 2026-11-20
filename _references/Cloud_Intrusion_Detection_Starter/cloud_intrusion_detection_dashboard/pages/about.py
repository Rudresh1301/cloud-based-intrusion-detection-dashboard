"""
About Project and Academic Technical Documentation.
Details project objectives, technical architecture, engineering methodologies,
technology stack, and educational project evaluation notes.
"""
import streamlit as st
from config.settings import (
    COLOR_CARD,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_ACCENT,
    COLOR_GREEN,
    COLOR_CYAN,
    APP_NAME,
    APP_VERSION,
)

def render_about():
    """Renders the comprehensive project overview page."""
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h2 style="color: {COLOR_TEXT}; margin-bottom: 4px;">ℹ️ About This Project</h2>
            <p style="color: {COLOR_MUTED}; font-size: 0.9rem;">
                Engineering documentation, architectural specifications, and educational mini-project evaluation summary.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Project Overview Card
    st.markdown(
        f"""
        <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 22px; margin-bottom: 20px;">
            <div style="font-size: 1.25rem; font-weight: 800; color: {COLOR_TEXT};">
                🛡️ {APP_NAME} <span style="font-size: 0.8rem; background: rgba(0,168,255,0.2); color: {COLOR_ACCENT}; padding: 3px 8px; border-radius: 6px;">v{APP_VERSION}</span>
            </div>
            <div style="font-size: 0.88rem; color: {COLOR_MUTED}; margin-top: 8px; line-height: 1.6;">
                A cloud-native Security Operations Center (SOC) dashboard developed as a 5th-semester engineering mini project.
                The system ingests, normalizes, inspects, and visualizes web application access and network interaction logs,
                utilizing dual-tier detection: deterministic rule-based signature heuristics and unsupervised machine learning (Isolation Forest)
                anomaly scoring.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 20px; height: 100%;">
                <div style="font-weight: 700; color: {COLOR_TEXT}; font-size: 1rem; margin-bottom: 12px;">
                    🎯 Key Objectives Achieved
                </div>
                <div style="font-size: 0.82rem; color: {COLOR_MUTED}; line-height: 1.8;">
                    <b>1. High-Density SOC Dashboard:</b> Professional dark navy interface with real-time attack curves and severity distribution.<br>
                    <b>2. Dual-Tier Intrusion Detection:</b> Regex/heuristic signatures combined with Scikit-Learn Isolation Forest outlier scoring.<br>
                    <b>3. Deep IP Intelligence:</b> Host-level behavioral profiling, failure metrics, target mapping, and threat scoring.<br>
                    <b>4. Interactive Alert Triage:</b> Mutable lifecycle states (New → Investigating → Resolved) with database persistence.<br>
                    <b>5. Automated Audit Reporting:</b> One-click PDF generation via ReportLab with executive recommendations.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 12px; padding: 20px; height: 100%;">
                <div style="font-weight: 700; color: {COLOR_TEXT}; font-size: 1rem; margin-bottom: 12px;">
                    ⚙️ Core Technology Stack
                </div>
                <div style="font-size: 0.82rem; color: {COLOR_MUTED}; line-height: 1.8;">
                    • <b>Programming:</b> Python 3.10+<br>
                    • <b>UI & Framework:</b> Streamlit 1.39+ with Custom CSS Glassmorphism<br>
                    • <b>Data Visualization:</b> Plotly Express & Plotly Graph Objects<br>
                    • <b>Data Engineering:</b> Pandas 2.2+ & NumPy 1.26+<br>
                    • <b>Machine Learning:</b> Scikit-Learn (Isolation Forest Outlier Detection)<br>
                    • <b>Storage / Cloud:</b> Google Firebase Firestore with SQLite3 fallback<br>
                    • <b>Report Compilation:</b> ReportLab PDF Document Engine
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.write("")

    # Detection Capabilities Grid
    st.markdown("#### 🛡️ Implemented Attack Signature Classifiers")
    sig_c1, sig_c2, sig_c3 = st.columns(3)

    with sig_c1:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 8px; padding: 12px;">
                <b style="color: {COLOR_ACCENT};">Brute-Force Detection</b><br>
                <span style="font-size: 0.8rem; color: {COLOR_MUTED};">Tracks consecutive failed logins per host with threshold escalation.</span>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.write("")
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 8px; padding: 12px;">
                <b style="color: {COLOR_ACCENT};">SQL Injection (SQLi)</b><br>
                <span style="font-size: 0.8rem; color: {COLOR_MUTED};">Inspects query parameters for UNION, SELECT, DROP, and OR 1=1 tokens.</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    with sig_c2:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 8px; padding: 12px;">
                <b style="color: {COLOR_ACCENT};">Cross-Site Scripting (XSS)</b><br>
                <span style="font-size: 0.8rem; color: {COLOR_MUTED};">Detects script tags, JS event handlers, and eval constructs.</span>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.write("")
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 8px; padding: 12px;">
                <b style="color: {COLOR_ACCENT};">Command Injection</b><br>
                <span style="font-size: 0.8rem; color: {COLOR_MUTED};">Identifies OS shell pipe commands (;ls, |cat, `whoami`, $(id)).</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    with sig_c3:
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 8px; padding: 12px;">
                <b style="color: {COLOR_ACCENT};">Path Traversal</b><br>
                <span style="font-size: 0.8rem; color: {COLOR_MUTED};">Catches ../ relative paths targeting /etc/passwd or win.ini.</span>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.write("")
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 8px; padding: 12px;">
                <b style="color: {COLOR_ACCENT};">ML Anomaly Detection</b><br>
                <span style="font-size: 0.8rem; color: {COLOR_MUTED};">Unsupervised multidimensional density isolation on host behavioral features.</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.write("")

    # Ethical and Educational Disclaimer
    st.markdown(
        f"""
        <div style="background: rgba(255, 176, 32, 0.08); border-left: 4px solid #FFB020; border-radius: 8px; padding: 14px; font-size: 0.82rem; color: {COLOR_TEXT};">
            <b>Educational Prototype Notice:</b> This project is engineered exclusively for academic, research, and educational demonstration purposes in a controlled laboratory setting. It analyzes uploaded or sample log telemetry and demonstrates the principles of Security Operations Center triage; it does not passively sniff live promiscuous network interfaces or block actual attacker packets on external hardware firewalls unless explicitly integrated with edge infrastructure.
        </div>
        """,
        unsafe_allow_html=True
    )
