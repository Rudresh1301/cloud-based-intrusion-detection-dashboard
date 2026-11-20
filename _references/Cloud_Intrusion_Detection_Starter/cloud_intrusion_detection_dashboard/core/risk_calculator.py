"""
Holistic Security Risk Assessment and Dynamic Remediation Engine.
Computes organizational threat posture, severity weightings, and tactical defensive steps.
"""
import pandas as pd
from config.settings import COLOR_RED, COLOR_ORANGE, COLOR_PURPLE, COLOR_GREEN, COLOR_CYAN

class RiskCalculator:
    """Calculates composite risk score and tailors remediation advice."""

    def calculate_overall_risk(self, alerts_df: pd.DataFrame, logs_df: pd.DataFrame) -> dict:
        """
        Calculates composite risk assessment based on actual findings.
        Returns:
            dict: {level, score, percentage, color, description, contributing_factors}
        """
        if alerts_df is None or alerts_df.empty:
            return {
                "level": "LOW RISK",
                "score": 8,
                "percentage": 8,
                "color": COLOR_GREEN,
                "description": "Clean operational profile. No active threat indicators detected.",
                "contributing_factors": ["No rule violations triggered", "Zero suspicious attack signatures"]
            }

        crit_count = int((alerts_df["severity"] == "Critical").sum())
        high_count = int((alerts_df["severity"] == "High").sum())
        med_count = int((alerts_df["severity"] == "Medium").sum())
        low_count = int((alerts_df["severity"] == "Low").sum())
        
        tot_threats = len(alerts_df)
        suspicious_ips = int(alerts_df["source_ip"].nunique())

        # Weighted calculation
        raw_score = (crit_count * 35) + (high_count * 20) + (med_count * 8) + (low_count * 2) + (suspicious_ips * 5)
        
        # Scale to 0-100
        score = min(100, max(15, raw_score))

        factors = []
        if crit_count > 0:
            factors.append(f"{crit_count} Critical severity threat(s) flagged")
        if high_count > 0:
            factors.append(f"{high_count} High severity incident(s) requiring attention")
        if suspicious_ips > 1:
            factors.append(f"{suspicious_ips} distinct hostile/anomalous IP hosts identified")
        
        if score >= 75 or crit_count >= 2:
            level = "CRITICAL RISK"
            color = COLOR_RED
            desc = "Imminent compromise indicators detected. Immediate incident response required!"
        elif score >= 50 or crit_count >= 1 or high_count >= 3:
            level = "HIGH RISK"
            color = COLOR_RED
            desc = "Multiple aggressive intrusion patterns detected. Immediate containment advised."
        elif score >= 25:
            level = "MEDIUM RISK"
            color = COLOR_ORANGE
            desc = "Elevated suspicious activity observed. Review alerted vectors and logs."
        else:
            level = "LOW RISK"
            color = COLOR_CYAN
            desc = "Low-severity anomalies observed within acceptable operational thresholds."

        return {
            "level": level,
            "score": score,
            "percentage": score,
            "color": color,
            "description": desc,
            "contributing_factors": factors or ["Anomalies isolated to low-tier events"]
        }

    def generate_recommendations(self, alerts_df: pd.DataFrame, logs_df: pd.DataFrame) -> list[str]:
        """
        Dynamically derives actionable security recommendations matching observed attacks.
        """
        if alerts_df is None or alerts_df.empty:
            return [
                "Maintain continuous baseline logging across all ingress proxies and API gateways.",
                "Review firewall rules and ensure periodic credential rotation for privileged service accounts.",
                "Ensure SSL/TLS termination is uniformly enforced across all public endpoints."
            ]

        attack_types = [str(t).lower() for t in alerts_df["alert_type"].unique()]
        recs = []

        if any("brute force" in t for t in attack_types):
            recs.append("Mitigate Brute Force: Deploy rate-limiting (fail2ban/WAF) on /login; enforce account lockout after 5 failed attempts.")
            recs.append("Authentication Hardening: Mandate multi-factor authentication (MFA) for administrative and remote access accounts.")

        if any("sql injection" in t for t in attack_types):
            recs.append("Neutralize SQL Injection: Audit database queries to ensure parameterized statements / ORM usage; block raw string concatenation.")
            recs.append("Database Least Privilege: Restrict web database user permissions (revoke DROP, EXECUTE, and file read rights).")

        if any("xss" in t for t in attack_types):
            recs.append("Prevent Cross-Site Scripting: Enforce Content Security Policy (CSP) headers and context-aware HTML entity encoding on user input.")

        if any("command injection" in t for t in attack_types):
            recs.append("Block Command Injection: Eliminate direct shell invocation (system, exec); apply strict input validation against shell meta-characters.")

        if any("path traversal" in t for t in attack_types):
            recs.append("Prevent Path Traversal: Restrict filesystem access via strict whitelist mapping; use chroot or file system permission boundaries.")

        if any("high request" in t for t in attack_types):
            recs.append("Traffic Shaping: Deploy Cloudflare/edge CDN token bucket rate limiting to mitigate scrapers and high-volume layer-7 floods.")

        # Default fallback recommendations if specific ones are few
        if len(recs) < 3:
            recs.append("Perimeter Control: Temporarily quarantine recurring offending IP addresses at edge security groups.")
            recs.append("Incident Logging: Export security logs and retain forensic audit trail in centralized cold storage.")

        return recs[:5]
