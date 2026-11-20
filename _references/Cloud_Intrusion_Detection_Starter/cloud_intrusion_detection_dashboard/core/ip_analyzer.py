"""
IP Address Intelligence and Deep Investigation Module.
Classifies IP ranges, calculates activity density, assesses per-host risk scores,
and correlates security alerts with host event timelines.
"""
import ipaddress
import pandas as pd
from datetime import datetime
from config.settings import COLOR_RED, COLOR_ORANGE, COLOR_PURPLE, COLOR_CYAN, COLOR_GREEN

class IPAnalyzer:
    """Analyzes behavioral footprints and risk posture for specific IP hosts."""

    def classify_ip(self, ip_str: str) -> str:
        """Classifies address into standard network zones."""
        try:
            ip_obj = ipaddress.ip_address(str(ip_str).strip())
            if ip_obj.is_loopback:
                return "Loopback (127.0.0.1)"
            elif ip_obj.is_private:
                return "Private Subnet (RFC 1918)"
            elif ip_obj.is_reserved:
                return "Reserved"
            elif ip_obj.is_multicast:
                return "Multicast"
            else:
                return "Public Internet"
        except ValueError:
            return "Unparseable / Invalid IP"

    def analyze_ip(self, ip: str, logs_df: pd.DataFrame, alerts_df: pd.DataFrame) -> dict:
        """
        Gathers comprehensive dossier for a single target IP address.
        """
        ip_str = str(ip).strip()
        ip_logs = logs_df[logs_df["source_ip"] == ip_str] if logs_df is not None and not logs_df.empty else pd.DataFrame()
        ip_alerts = alerts_df[alerts_df["source_ip"] == ip_str] if alerts_df is not None and not alerts_df.empty else pd.DataFrame()

        total_events = len(ip_logs)
        alert_count = len(ip_alerts)

        if total_events == 0 and alert_count == 0:
            return {
                "ip": ip_str,
                "classification": self.classify_ip(ip_str),
                "found": False,
                "message": f"No events or alerts recorded for {ip_str} in the analyzed logs."
            }

        # Failed events
        status_s = ip_logs["status"].astype(str).str.lower()
        failed_count = int(status_s.isin(["failed", "failure", "denied", "401", "403"]).sum())
        blocked_count = int(status_s.isin(["blocked", "dropped", "rejected"]).sum())
        success_count = int(status_s.isin(["success", "ok", "200"]).sum())
        failed_ratio = failed_count / (total_events if total_events > 0 else 1)

        # Unique endpoints and users
        endpoints = list(ip_logs["endpoint"].unique()) if "endpoint" in ip_logs.columns else []
        usernames = list(ip_logs["username"].unique()) if "username" in ip_logs.columns else []

        # Timestamps
        if "timestamp_dt" in ip_logs.columns and pd.api.types.is_datetime64_any_dtype(ip_logs["timestamp_dt"]):
            ts_parsed = ip_logs["timestamp_dt"].dropna()
        else:
            ts_parsed = pd.to_datetime(ip_logs["timestamp"], errors="coerce").dropna()
        first_seen = ts_parsed.min().strftime("%Y-%m-%d %H:%M:%S") if not ts_parsed.empty else "N/A"
        last_seen = ts_parsed.max().strftime("%Y-%m-%d %H:%M:%S") if not ts_parsed.empty else "N/A"

        # Threat types
        threat_types = list(ip_alerts["alert_type"].unique()) if not ip_alerts.empty else []
        severities = list(ip_alerts["severity"].unique()) if not ip_alerts.empty else []

        # Risk score calculation (0 - 100)
        risk_score = 0
        if "Critical" in severities:
            risk_score += 45
        elif "High" in severities:
            risk_score += 30
        elif "Medium" in severities:
            risk_score += 15

        risk_score += min(30, alert_count * 5)
        risk_score += min(15, int(failed_ratio * 20))
        if len(threat_types) > 1:
            risk_score += 10
        risk_score = min(100, max(0, risk_score))

        # Risk classification
        if risk_score >= 70:
            risk_level = "Critical"
            risk_color = COLOR_RED
        elif risk_score >= 45:
            risk_level = "High"
            risk_color = COLOR_ORANGE
        elif risk_score >= 20:
            risk_level = "Medium"
            risk_color = COLOR_PURPLE
        elif risk_score > 0:
            risk_level = "Low"
            risk_color = COLOR_CYAN
        else:
            risk_level = "Clean"
            risk_color = COLOR_GREEN

        return {
            "ip": ip_str,
            "classification": self.classify_ip(ip_str),
            "found": True,
            "total_events": total_events,
            "alert_count": alert_count,
            "failed_events": failed_count,
            "blocked_events": blocked_count,
            "success_events": success_count,
            "failed_ratio": round(failed_ratio, 2),
            "endpoints": endpoints,
            "usernames": usernames,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "threat_types": threat_types,
            "severities": severities,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "alerts_df": ip_alerts,
            "logs_df": ip_logs
        }

    def get_top_suspicious_ips(self, alerts_df: pd.DataFrame, logs_df: pd.DataFrame, top_n: int = 10) -> list[dict]:
        """
        Aggregates and ranks the most threatening IP addresses.
        """
        if alerts_df is None or alerts_df.empty:
            return []

        results = []
        for ip, grp in alerts_df.groupby("source_ip"):
            alert_count = len(grp)
            highest_sev = "Low"
            for s in ["Critical", "High", "Medium", "Low"]:
                if s in grp["severity"].values:
                    highest_sev = s
                    break

            ip_logs = logs_df[logs_df["source_ip"] == ip] if logs_df is not None and not logs_df.empty else pd.DataFrame()
            total_evs = len(ip_logs)
            last_ts = grp["timestamp"].max()

            results.append({
                "source_ip": str(ip),
                "count": alert_count,
                "severity": highest_sev,
                "total_events": total_evs,
                "last_seen": str(last_ts),
                "threat_types": ", ".join(grp["alert_type"].unique()[:2]),
                "evidence": grp["evidence"].iloc[0] if not grp.empty else "Suspicious activities detected"
            })

        # Rank by count and severity weight
        sev_weights = {"Critical": 1000, "High": 100, "Medium": 10, "Low": 1}
        results.sort(key=lambda x: (sev_weights.get(x["severity"], 0) * 10 + x["count"]), reverse=True)
        return results[:top_n]
