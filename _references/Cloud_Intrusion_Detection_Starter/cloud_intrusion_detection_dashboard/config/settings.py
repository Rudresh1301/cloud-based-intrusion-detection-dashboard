"""
Central configuration for Cloud-Based Intrusion Detection Dashboard.
All settings, thresholds, color palette, and application constants.
"""

# ── Application ─────────────────────────────────────────────
APP_NAME = "Cloud-Based Intrusion Detection Dashboard"
APP_SHORT = "Cloud IDS"
APP_VERSION = "2.0.0"
APP_TAGLINE = "Monitor • Detect • Protect"

# ── Approved Colour Palette (DO NOT CHANGE) ─────────────────
COLOR_BG = "#080D19"
COLOR_SIDEBAR = "#0D1526"
COLOR_CARD = "#121E32"
COLOR_ACCENT = "#00A8FF"
COLOR_ELECTRIC = "#087FE5"
COLOR_CYAN = "#00C8FF"
COLOR_PURPLE = "#8B5CF6"
COLOR_RED = "#FF4560"
COLOR_ORANGE = "#FFB020"
COLOR_GREEN = "#00D68F"
COLOR_TEXT = "#F1F5F9"
COLOR_MUTED = "#9CC9E8"
COLOR_BORDER = "#164879"
COLOR_PANEL = "#0D192B"
COLOR_PANEL_BORDER = "#153B61"
COLOR_GRID = "#1B3451"

SEVERITY_COLORS = {
    "Critical": COLOR_RED,
    "High": COLOR_ORANGE,
    "Medium": COLOR_PURPLE,
    "Low": COLOR_CYAN,
}

STATUS_COLORS = {
    "New": COLOR_ACCENT,
    "Investigating": COLOR_ORANGE,
    "Resolved": COLOR_GREEN,
    "False Positive": "#6B7280",
}

# ── Detection Thresholds ────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_CRITICAL = 10
HIGH_VOLUME_THRESHOLD = 50
RAPID_REQUEST_SECONDS = 1

# ── ML Settings ─────────────────────────────────────────────
ML_CONTAMINATION = 0.1
ML_MIN_SAMPLES = 10
ML_RANDOM_STATE = 42

# ── Database ────────────────────────────────────────────────
DB_MODES = ("firebase", "local")
LOCAL_DB_PATH = "data/local_ids.db"

# ── Upload ──────────────────────────────────────────────────
SUPPORTED_FILE_TYPES = ["csv", "txt"]
MAX_UPLOAD_MB = 50
REQUIRED_COLUMNS = ["timestamp", "source_ip", "username", "event_type", "status", "endpoint"]

# ── Pagination ──────────────────────────────────────────────
ITEMS_PER_PAGE = 25

# ── Severity & Status ──────────────────────────────────────
SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low"]
ALERT_STATUSES = ["New", "Investigating", "Resolved", "False Positive"]

# ── Attack Categories ──────────────────────────────────────
ATTACK_CATEGORIES = [
    "Brute Force",
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Command Injection",
    "Path Traversal",
    "High Request Volume",
    "Unusual Access Pattern",
    "ML Anomaly",
]

# ── Sensitive Endpoints ────────────────────────────────────
SENSITIVE_ENDPOINTS = [
    "/admin", "/config", "/debug", "/backup", "/wp-admin",
    "/phpmyadmin", "/administrator", "/cpanel", "/manager",
    "/console", "/.env", "/server-status", "/wp-login",
]

# ── Session-state helpers ──────────────────────────────────
def _ss():
    """Lazy import to avoid circular dependency at module level."""
    import streamlit as st
    return st.session_state


def get_setting(key: str, default=None):
    """Read a setting from session state, falling back to module default."""
    ss = _ss()
    settings = ss.get("settings", {})
    if key in settings:
        return settings[key]
    # fall back to module-level constant
    val = globals().get(key, default)
    return val if val is not None else default


def update_setting(key: str, value):
    """Write a setting into session state."""
    ss = _ss()
    if "settings" not in ss:
        ss["settings"] = {}
    ss["settings"][key] = value


def get_default_settings() -> dict:
    """Return a copy of the default settings dict."""
    return {
        "BRUTE_FORCE_THRESHOLD": BRUTE_FORCE_THRESHOLD,
        "BRUTE_FORCE_CRITICAL": BRUTE_FORCE_CRITICAL,
        "HIGH_VOLUME_THRESHOLD": HIGH_VOLUME_THRESHOLD,
        "ML_CONTAMINATION": ML_CONTAMINATION,
        "ML_MIN_SAMPLES": ML_MIN_SAMPLES,
        "ML_ENABLED": True,
        "XSS_DETECTION": True,
        "CMD_INJECTION_DETECTION": True,
        "PATH_TRAVERSAL_DETECTION": True,
        "ITEMS_PER_PAGE": ITEMS_PER_PAGE,
    }
