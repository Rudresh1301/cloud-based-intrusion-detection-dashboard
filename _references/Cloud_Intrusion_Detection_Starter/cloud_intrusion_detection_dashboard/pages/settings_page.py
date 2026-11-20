"""
System Preferences, Detection Thresholds & Database Configuration.
Allows dynamic tuning of brute-force heuristics, volumetric flood thresholds,
machine learning hyperparameters, and cloud database connectivity.
"""
import streamlit as st
from config.settings import (
    COLOR_CARD,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_ACCENT,
    COLOR_GREEN,
    COLOR_RED,
    COLOR_ORANGE,
    get_setting,
    update_setting,
    get_default_settings,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_CRITICAL,
    HIGH_VOLUME_THRESHOLD,
    ML_CONTAMINATION,
    ITEMS_PER_PAGE,
)
from config.firebase_config import get_db_status

def render_settings():
    """Renders the settings and system configuration interface."""
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h2 style="color: {COLOR_TEXT}; margin-bottom: 4px;">⚙️ Engine Settings & Preferences</h2>
            <p style="color: {COLOR_MUTED}; font-size: 0.9rem;">
                Adjust heuristic detection sensitivity, volumetric thresholds, machine learning contamination, and cloud storage links.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    tab_rules, tab_ml, tab_db, tab_info = st.tabs([
        "🛡️ Detection Heuristics",
        "🧠 Machine Learning Settings",
        "☁️ Cloud & Database",
        "ℹ️ System Specifications"
    ])

    # ── Tab 1: Heuristic Rules Configuration ─────────────────────
    with tab_rules:
        st.markdown("#### Rule-Based Detection Thresholds")
        st.caption("Adjusting these parameters dynamically alters detection sensitivity on next log analysis.")

        c1, c2 = st.columns(2)
        with c1:
            bf_thresh = st.number_input(
                "Brute Force Warning Threshold (Failed Logins)",
                min_value=2,
                max_value=50,
                value=int(get_setting("BRUTE_FORCE_THRESHOLD", BRUTE_FORCE_THRESHOLD)),
                help="Number of failed logins from a single IP before generating a High severity alert."
            )
            bf_crit = st.number_input(
                "Brute Force Critical Threshold",
                min_value=5,
                max_value=100,
                value=int(get_setting("BRUTE_FORCE_CRITICAL", BRUTE_FORCE_CRITICAL)),
                help="Threshold of failed attempts for Critical alert escalation."
            )
            vol_thresh = st.number_input(
                "High Request Volume Flood Threshold",
                min_value=10,
                max_value=1000,
                value=int(get_setting("HIGH_VOLUME_THRESHOLD", HIGH_VOLUME_THRESHOLD)),
                help="Request count from an IP that flags volumetric scanning / denial of service."
            )

        with c2:
            xss_toggle = st.toggle("Enable Cross-Site Scripting (XSS) Signatures", value=get_setting("XSS_DETECTION", True))
            cmd_toggle = st.toggle("Enable OS Command Injection Signatures", value=get_setting("CMD_INJECTION_DETECTION", True))
            path_toggle = st.toggle("Enable Path Traversal (LFI/RFI) Signatures", value=get_setting("PATH_TRAVERSAL_DETECTION", True))
            page_size = st.number_input("Log Viewer Pagination Rows", min_value=10, max_value=100, value=int(get_setting("ITEMS_PER_PAGE", ITEMS_PER_PAGE)))

        st.write("")
        if st.button("💾 Save Heuristic Settings", type="primary"):
            update_setting("BRUTE_FORCE_THRESHOLD", bf_thresh)
            update_setting("BRUTE_FORCE_CRITICAL", bf_crit)
            update_setting("HIGH_VOLUME_THRESHOLD", vol_thresh)
            update_setting("XSS_DETECTION", xss_toggle)
            update_setting("CMD_INJECTION_DETECTION", cmd_toggle)
            update_setting("PATH_TRAVERSAL_DETECTION", path_toggle)
            update_setting("ITEMS_PER_PAGE", page_size)
            st.session_state.reanalyze_trigger = True
            st.success("Detection settings successfully updated and applied! Re-running analysis...")
            st.rerun()

    # ── Tab 2: Machine Learning Tuning ───────────────────────────
    with tab_ml:
        st.markdown("#### Unsupervised Anomaly Detection (Isolation Forest)")
        st.caption("Configures the behavioral density model used for clustering anomalous host vectors.")

        ml_enabled = st.toggle("Enable Isolation Forest Anomaly Pipeline", value=get_setting("ML_ENABLED", True))
        contamination = st.slider(
            "Estimated Outlier Contamination Rate",
            min_value=0.01,
            max_value=0.30,
            value=float(get_setting("ML_CONTAMINATION", ML_CONTAMINATION)),
            step=0.01,
            help="Proportion of outliers expected in network telemetry (standard: 0.05 - 0.15)."
        )

        st.info("Feature Set Vector: [request_count, failed_count, failed_ratio, unique_endpoints, unique_users, suspicious_keyword_count, unique_event_types]")

        if st.button("💾 Save ML Parameters"):
            update_setting("ML_ENABLED", ml_enabled)
            update_setting("ML_CONTAMINATION", contamination)
            st.session_state.reanalyze_trigger = True
            st.success("ML hyperparameters updated! Re-evaluating anomalies...")
            st.rerun()

    # ── Tab 3: Database & Cloud Configuration ────────────────────
    with tab_db:
        st.markdown("#### Storage Architecture Status")
        db_stat = get_db_status()
        
        mode_badge = f"<span style='color: {COLOR_GREEN}; font-weight: bold;'>☁️ Firebase Firestore</span>" if db_stat["mode"] == "firebase" else f"<span style='color: {COLOR_ORANGE}; font-weight: bold;'>💾 Local SQLite (Fallback)</span>"
        
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 10px; padding: 16px; margin-bottom: 15px;">
                <div style="font-size: 0.9rem; color: {COLOR_MUTED};">Current Active Storage Mode:</div>
                <div style="font-size: 1.2rem; margin-top: 4px;">{mode_badge}</div>
                <div style="font-size: 0.8rem; color: {COLOR_MUTED}; margin-top: 6px;">Status: <b>{db_stat['message']}</b></div>
            </div>
            """,
            unsafe_allow_html=True
        )

        with st.expander("🛠️ How to Connect Firebase Cloud Firestore", expanded=(db_stat["mode"] == "local")):
            st.markdown(
                """
                To connect this project to Google Firebase Firestore for cloud persistence:
                
                1. Navigate to the **Firebase Console** (https://console.firebase.google.com).
                2. Create a project and enable **Cloud Firestore** in test or production mode.
                3. Go to **Project Settings** > **Service Accounts** and click **Generate new private key**.
                4. Save the downloaded JSON file as `firebase_credentials.json` in the root directory.
                5. Alternatively, for Streamlit Cloud deployment, add the JSON contents under `st.secrets["firebase"]`.
                """
            )

    # ── Tab 4: System Specifications ─────────────────────────────
    with tab_info:
        st.markdown("#### SOC Engine Build Specifications")
        st.markdown(
            f"""
            <div style="background: {COLOR_CARD}; border: 1px solid #164879; border-radius: 10px; padding: 18px; font-size: 0.85rem; color: {COLOR_MUTED}; line-height: 2;">
                • <b>Application Version:</b> 2.0.0 (SOC Production Ready)<br>
                • <b>Detection Core:</b> Rule Engine v2 + Scikit-Learn IsolationForest<br>
                • <b>Data Processing:</b> Pandas 2.2+ vectorized routines<br>
                • <b>Visual Framework:</b> Plotly 5.24+ Dark Navy Holographic Palette<br>
                • <b>Reporting:</b> ReportLab PDF Audit Generation<br>
                • <b>Host Environment:</b> Streamlit 1.39+ Framework
            </div>
            """,
            unsafe_allow_html=True
        )
