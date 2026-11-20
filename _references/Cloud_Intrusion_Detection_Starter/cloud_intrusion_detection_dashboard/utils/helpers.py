"""
General helper utilities for UI formatting, date math, colors, and string safety.
"""
import re
import ipaddress
import uuid
import html
from datetime import datetime, timedelta
import pandas as pd
from config.settings import (
    SEVERITY_COLORS,
    STATUS_COLORS,
    COLOR_RED,
    COLOR_ORANGE,
    COLOR_PURPLE,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_ACCENT
)

def format_number(val) -> str:
    """Format number with thousands comma separator."""
    try:
        val = int(val)
        return f"{val:,}"
    except (ValueError, TypeError):
        return str(val)

def format_timestamp(ts) -> str:
    """Standardize timestamp to YYYY-MM-DD HH:MM:SS format string."""
    if pd.isna(ts) or ts is None or str(ts).strip() == "":
        return "N/A"
    try:
        dt = pd.to_datetime(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

def format_time_only(ts) -> str:
    """Format timestamp to HH:MM AM/PM."""
    try:
        dt = pd.to_datetime(ts)
        return dt.strftime("%I:%M %p")
    except Exception:
        return str(ts)

def time_ago(ts) -> str:
    """Human-friendly relative time string."""
    try:
        dt = pd.to_datetime(ts)
        now = datetime.now()
        diff = now - dt
        seconds = diff.total_seconds()
        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            m = int(seconds // 60)
            return f"{m} min{'s' if m > 1 else ''} ago"
        elif seconds < 86400:
            h = int(seconds // 3600)
            return f"{h} hr{'s' if h > 1 else ''} ago"
        else:
            d = int(seconds // 86400)
            return f"{d} day{'s' if d > 1 else ''} ago"
    except Exception:
        return "recently"

def get_severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(str(severity).capitalize(), COLOR_CYAN)

def get_status_color(status: str) -> str:
    return STATUS_COLORS.get(str(status).title(), "#6B7280")

def get_severity_badge_html(severity: str) -> str:
    color = get_severity_color(severity)
    sev_upper = str(severity).upper()
    return f"""<span style="background-color: {color}22; color: {color}; border: 1px solid {color}55; padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; display: inline-block;">{sev_upper}</span>"""

def get_status_badge_html(status: str) -> str:
    color = get_status_color(status)
    return f"""<span style="background-color: {color}22; color: {color}; border: 1px solid {color}55; padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; display: inline-block;">{status}</span>"""

def calculate_percentage_change(current: float, previous: float) -> tuple[str, str, str]:
    """
    Returns (formatted_string, trend_class, arrow).
    trend_class: 'up' (positive) or 'down' (negative).
    """
    if previous == 0 or pd.isna(previous):
        return ("+0%", "up", "↑")
    diff = current - previous
    pct = (diff / previous) * 100
    arrow = "↑" if pct >= 0 else "↓"
    sign = "+" if pct >= 0 else ""
    trend_class = "up" if pct >= 0 else "down"
    return (f"{arrow} {sign}{pct:.1f}%", trend_class, arrow)

def get_risk_level(threat_count: int, total_events: int) -> dict:
    """
    Computes system risk rating based on threat volume and event ratios.
    """
    if total_events == 0:
        return {
            "level": "LOW",
            "score": 5,
            "percentage": 5,
            "color": COLOR_GREEN,
            "description": "System operating normally. No threats detected.",
        }
    
    ratio = threat_count / total_events
    score = min(100, int(ratio * 150 + (threat_count * 2)))
    
    if score >= 75 or threat_count >= 20:
        return {
            "level": "CRITICAL RISK",
            "score": max(85, score),
            "percentage": max(85, score),
            "color": COLOR_RED,
            "description": "Severe intrusion indicators detected! Immediate containment required.",
        }
    elif score >= 50 or threat_count >= 10:
        return {
            "level": "HIGH RISK",
            "score": max(70, score),
            "percentage": max(70, score),
            "color": COLOR_RED,
            "description": "Multiple suspicious threats identified. Immediate attention required!",
        }
    elif score >= 25 or threat_count >= 3:
        return {
            "level": "MEDIUM RISK",
            "score": max(45, score),
            "percentage": max(45, score),
            "color": COLOR_ORANGE,
            "description": "Moderate suspicious activities observed. Investigation advised.",
        }
    else:
        return {
            "level": "LOW RISK",
            "score": max(15, score),
            "percentage": max(15, score),
            "color": COLOR_GREEN,
            "description": "Minor anomalies observed within acceptable operational margins.",
        }

def sanitize_string(s: str) -> str:
    """Escapes HTML entities to prevent stored or reflected XSS in dashboard."""
    if s is None:
        return ""
    return html.escape(str(s))

def validate_ip(ip_str: str) -> bool:
    """Checks if string is a valid IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False

def truncate_string(s: str, max_len: int = 50) -> str:
    if not s:
        return ""
    s = str(s)
    if len(s) > max_len:
        return s[:max_len - 3] + "..."
    return s

def safe_divide(a: float, b: float, default: float = 0.0) -> float:
    try:
        if b == 0 or pd.isna(b):
            return default
        return a / b
    except Exception:
        return default

def generate_id() -> str:
    return str(uuid.uuid4())
