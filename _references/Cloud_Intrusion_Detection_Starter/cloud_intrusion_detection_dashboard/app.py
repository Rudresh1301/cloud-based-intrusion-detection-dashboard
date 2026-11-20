"""
Cloud-Based Intrusion Detection Dashboard.
Main Streamlit application entry point.
Implements the complete dark navy SOC interface, holographic accents, sidebar navigation,
session state lifecycle, and dynamic page routing.
"""
from pathlib import Path
import streamlit as st
import pandas as pd

# Page Configuration MUST be the first Streamlit call
st.set_page_config(
    page_title="Cloud-Based Intrusion Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Import Core Engine and Configurations
from config.settings import (
    COLOR_BG,
    COLOR_SIDEBAR,
    COLOR_CARD,
    COLOR_ACCENT,
    COLOR_ELECTRIC,
    COLOR_CYAN,
    COLOR_PURPLE,
    COLOR_RED,
    COLOR_ORANGE,
    COLOR_GREEN,
    COLOR_TEXT,
    COLOR_MUTED,
    COLOR_GRID,
    APP_NAME,
    APP_TAGLINE,
)
from config.firebase_config import get_db_status
from core.detector import IntrusionDetector
from core.log_processor import LogProcessor

# Import Page Renderers
from pages.dashboard import render_dashboard
from pages.upload_logs import render_upload_logs
from pages.live_monitoring import render_live_monitoring
from pages.threat_analysis import render_threat_analysis
from pages.ip_intelligence import render_ip_intelligence
from pages.attack_analytics import render_attack_analytics
from pages.security_logs import render_security_logs
from pages.alerts_center import render_alerts_center
from pages.reports import render_reports
from pages.settings_page import render_settings
from pages.about import render_about

SAMPLE_LOGS_PATH = Path(__file__).parent / "data" / "sample_logs.csv"

# ── Inject Global Custom SOC CSS ────────────────────────────────
st.markdown(
    f"""
    <style>
    /* Global Background and Fonts */
    html, body, [class*="css"], .stApp {{
        background-color: {COLOR_BG} !important;
        color: {COLOR_TEXT} !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}

    /* Sidebar Styling */
    [data-testid="stSidebar"] {{
        background-color: {COLOR_SIDEBAR} !important;
        border-right: 1px solid #12345A !important;
    }}
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {{
        color: {COLOR_TEXT} !important;
    }}

    /* Remove default Streamlit top header padding */
    .block-container {{
        padding-top: 1.2rem !important;
        padding-bottom: 2rem !important;
        max-width: 98% !important;
    }}

    /* Headings */
    h1, h2, h3, h4, h5, h6 {{
        color: {COLOR_TEXT} !important;
        font-weight: 700 !important;
        letter-spacing: -0.3px;
    }}

    /* SOC Card Container */
    .soc-card {{
        background: linear-gradient(135deg, #122541 0%, #101E35 100%) !important;
        border: 1px solid #164879 !important;
        border-radius: 14px !important;
        padding: 18px 20px !important;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35) !important;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }}
    .soc-card:hover {{
        border-color: {COLOR_ACCENT} !important;
        transform: translateY(-2px);
    }}

    /* Tables & DataFrames */
    div[data-testid="stDataFrame"] {{
        background: {COLOR_CARD} !important;
        border: 1px solid #153B61 !important;
        border-radius: 10px !important;
        overflow: hidden !important;
    }}

    /* Buttons */
    .stButton > button {{
        background: linear-gradient(90deg, {COLOR_ELECTRIC}, {COLOR_ACCENT}) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 0.88rem !important;
        padding: 0.5rem 1rem !important;
        box-shadow: 0 2px 10px rgba(0, 168, 255, 0.25) !important;
        transition: all 0.2s ease !important;
    }}
    .stButton > button:hover {{
        box-shadow: 0 4px 18px rgba(0, 168, 255, 0.45) !important;
        transform: translateY(-1px);
    }}

    /* Secondary Buttons */
    .stButton > button[kind="secondary"] {{
        background: #121E32 !important;
        border: 1px solid #164879 !important;
        color: {COLOR_TEXT} !important;
    }}

    /* Download Buttons */
    .stDownloadButton > button {{
        background: linear-gradient(90deg, #087FE5, #00A8FF) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 0.88rem !important;
        box-shadow: 0 2px 10px rgba(0, 168, 255, 0.25) !important;
    }}

    /* Form Inputs & Selects */
    div[data-baseweb="select"] > div,
    div[data-baseweb="input"] > div {{
        background-color: #0D192B !important;
        border: 1px solid #153B61 !important;
        color: {COLOR_TEXT} !important;
        border-radius: 8px !important;
    }}
    input {{
        color: {COLOR_TEXT} !important;
    }}

    /* Metrics Styling */
    div[data-testid="stMetricValue"] {{
        color: {COLOR_TEXT} !important;
        font-weight: 800 !important;
        font-size: 1.8rem !important;
    }}
    div[data-testid="stMetricLabel"] {{
        color: {COLOR_MUTED} !important;
        font-size: 0.82rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
    }}

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {{
        background-color: transparent !important;
        border-bottom: 1px solid #153B61 !important;
        gap: 8px;
    }}
    .stTabs [data-baseweb="tab"] {{
        color: {COLOR_MUTED} !important;
        font-weight: 600 !important;
        border-radius: 8px 8px 0 0 !important;
        padding: 8px 16px !important;
    }}
    .stTabs [aria-selected="true"] {{
        color: {COLOR_ACCENT} !important;
        border-bottom: 2px solid {COLOR_ACCENT} !important;
    }}

    /* Scrollbars */
    ::-webkit-scrollbar {{
        width: 6px;
        height: 6px;
    }}
    ::-webkit-scrollbar-track {{
        background: {COLOR_BG};
    }}
    ::-webkit-scrollbar-thumb {{
        background: #164879;
        border-radius: 3px;
    }}
    ::-webkit-scrollbar-thumb:hover {{
        background: {COLOR_ACCENT};
    }}

    /* Radio navigation options in sidebar */
    div[data-testid="stSidebar"] div[role="radiogroup"] > label {{
        background: transparent !important;
        padding: 8px 12px !important;
        border-radius: 8px !important;
        margin-bottom: 2px !important;
        transition: background 0.2s ease;
    }}
    div[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {{
        background: rgba(0, 168, 255, 0.08) !important;
    }}
    div[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] {{
        background: linear-gradient(90deg, #087FE5 0%, #00A8FF 100%) !important;
        box-shadow: 0 4px 14px rgba(8, 127, 229, 0.35) !important;
    }}
    div[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] p {{
        color: white !important;
        font-weight: 700 !important;
    }}
    </style>
    """,
    unsafe_allow_html=True
)

# ── Session State Lifecycle Initialization ──────────────────────
@st.cache_data(show_spinner=False)
def get_cached_sample_logs(path_str: str) -> pd.DataFrame:
    try:
        return pd.read_csv(path_str)
    except Exception:
        try:
            return pd.read_csv(path_str, on_bad_lines='skip')
        except Exception:
            return pd.DataFrame()

if "logs" not in st.session_state:
    if SAMPLE_LOGS_PATH.exists():
        st.session_state.logs = get_cached_sample_logs(str(SAMPLE_LOGS_PATH))
    else:
        st.session_state.logs = pd.DataFrame()

if "analysis_results" not in st.session_state or st.session_state.get("reanalyze_trigger", False):
    with st.spinner("Analyzing telemetry with rule heuristics & ML anomaly detection..."):
        detector = IntrusionDetector()
        st.session_state.analysis_results = detector.analyze(st.session_state.logs)
    st.session_state.reanalyze_trigger = False

# ── Sidebar Brand Header ─────────────────────────────────────────
with st.sidebar:
    st.markdown(
        f"""
        <div style="text-align: center; padding: 12px 0 16px 0;">
            <div style="width: 56px; height: 56px; margin: 0 auto; background: radial-gradient(circle, rgba(0,168,255,0.2) 0%, rgba(8,13,25,0) 70%); border: 1.5px solid {COLOR_ACCENT}; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.6rem; box-shadow: 0 0 18px rgba(0,168,255,0.35);">
                🛡️
            </div>
            <div style="font-size: 1.05rem; font-weight: 800; color: {COLOR_TEXT}; margin-top: 10px; line-height: 1.3;">
                Cloud-Based<br>Intrusion Detection
            </div>
            <div style="font-size: 0.72rem; color: {COLOR_MUTED}; letter-spacing: 1.5px; text-transform: uppercase; margin-top: 4px;">
                {APP_TAGLINE}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Sidebar Navigation Menu (All 11 mandatory items)
    nav_options = [
        "Dashboard",
        "Upload Logs",
        "Live Monitoring",
        "Threat Analysis",
        "IP Intelligence",
        "Attack Analytics",
        "Security Logs",
        "Alerts Center",
        "Reports",
        "Settings",
        "About Project",
    ]

    # Map icons
    nav_icons = {
        "Dashboard": "📊 Dashboard",
        "Upload Logs": "📤 Upload Logs",
        "Live Monitoring": "📡 Live Monitoring",
        "Threat Analysis": "🎯 Threat Analysis",
        "IP Intelligence": "🌐 IP Intelligence",
        "Attack Analytics": "📈 Attack Analytics",
        "Security Logs": "📋 Security Logs",
        "Alerts Center": "🚨 Alerts Center",
        "Reports": "📄 Reports",
        "Settings": "⚙️ Settings",
        "About Project": "ℹ️ About Project",
    }

    selected_page_icon = st.radio(
        "NAVIGATION",
        options=[nav_icons[o] for o in nav_options],
        index=0,
        label_visibility="collapsed"
    )

    # Reverse-lookup page name
    current_page = next(k for k, v in nav_icons.items() if v == selected_page_icon)

    st.markdown("---")

    # ── Sidebar Status Footer ────────────────────────────────────
    db_stat = get_db_status()
    db_label = "☁️ Cloud Firebase" if db_stat["mode"] == "firebase" else "💾 Local SQLite"

    st.markdown(
        f"""
        <div style="padding: 10px 12px; background: rgba(18, 30, 50, 0.7); border: 1px solid #164879; border-radius: 10px; font-size: 0.78rem;">
            <div style="display: flex; align-items: center; gap: 6px; color: {COLOR_GREEN}; font-weight: bold; margin-bottom: 4px;">
                <span style="height: 7px; width: 7px; background-color: {COLOR_GREEN}; border-radius: 50%; box-shadow: 0 0 6px {COLOR_GREEN};"></span>
                System Online
            </div>
            <div style="color: {COLOR_MUTED};">Database: <b style="color: {COLOR_TEXT};">{db_label}</b></div>
            <div style="color: {COLOR_MUTED}; font-size: 0.72rem; margin-top: 4px;">Last Analyzed: 20 Nov 2026, 08:15 PM</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Decorative bottom hologram shield matching reference
    st.markdown(
        f"""
        <div style="text-align: center; margin-top: 25px; opacity: 0.65;">
            <div style="font-size: 2.2rem; filter: drop-shadow(0 0 10px {COLOR_ACCENT});">
                🛡️
            </div>
            <div style="font-size: 0.65rem; color: {COLOR_MUTED}; letter-spacing: 1px; margin-top: 2px;">
                SECURITY OPERATIONS CENTER
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

# ── Dynamic Page Routing ────────────────────────────────────────
analysis = st.session_state.analysis_results

if current_page == "Dashboard":
    render_dashboard(analysis)
elif current_page == "Upload Logs":
    render_upload_logs()
elif current_page == "Live Monitoring":
    render_live_monitoring()
elif current_page == "Threat Analysis":
    render_threat_analysis(analysis)
elif current_page == "IP Intelligence":
    render_ip_intelligence(analysis)
elif current_page == "Attack Analytics":
    render_attack_analytics(analysis)
elif current_page == "Security Logs":
    render_security_logs(analysis)
elif current_page == "Alerts Center":
    render_alerts_center(analysis)
elif current_page == "Reports":
    render_reports(analysis)
elif current_page == "Settings":
    render_settings()
elif current_page == "About Project":
    render_about()
