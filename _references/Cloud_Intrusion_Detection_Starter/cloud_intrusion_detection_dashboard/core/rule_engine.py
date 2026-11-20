"""
Rule-Based Intrusion Detection Engine (High-Performance Vectorized Implementation).
Implements deterministic heuristics, precompiled regex scanning, vectorized filtering,
and signature inspection for web & network application logs.
"""
import re
import uuid
import pandas as pd
from datetime import datetime
from config.settings import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_CRITICAL,
    HIGH_VOLUME_THRESHOLD,
    SENSITIVE_ENDPOINTS,
    get_setting,
)

class RuleEngine:
    """
    Evaluates log events against threat rules using vectorized regex & pandas operations:
    - Brute Force Login Detection
    - SQL Injection (SQLi)
    - Cross-Site Scripting (XSS)
    - Command Injection (RCE)
    - Path Traversal (LFI/RFI)
    - High Request Flooding
    - Sensitive Endpoint Probing
    """

    # Precompile regexes once at class level for instant reuse
    sqli_patterns = [
        r"(\bUNION\b\s+(\bALL\b\s+)?\bSELECT\b)",
        r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
        r"(\bOR\b\s+['\"][^'\"]+['\"]\s*=\s*['\"][^'\"]+)",
        r"(--|\#|\/\*|\*\/)",
        r"(\bDROP\b\s+\bTABLE\b)",
        r"(\bINSERT\b\s+\bINTO\b)",
        r"(\bDELETE\b\s+\bFROM\b)",
        r"(\bEXEC(\b|\s+)|xp_cmdshell)",
        r"(\bBENCHMARK\s*\(|\bSLEEP\s*\(\d+\))",
        r"(\bORDER\s+BY\s+\d+)",
    ]
    sqli_regex = re.compile("|".join(sqli_patterns), re.IGNORECASE)

    xss_patterns = [
        r"(<\s*script[^>]*>.*?<\s*\/\s*script\s*>)",
        r"(<\s*script[^>]*>)",
        r"(javascript\s*:\s*[^\s]+)",
        r"(onerror\s*=\s*['\"][^'\"]*['\"])",
        r"(onload\s*=\s*['\"][^'\"]*['\"])",
        r"(onclick\s*=\s*['\"][^'\"]*['\"])",
        r"(document\.cookie)",
        r"(<\s*img[^>]+src\s*=\s*[^>]*onerror)",
        r"(<\s*iframe[^>]*>)",
        r"(\balert\s*\([^\)]*\))",
        r"(\beval\s*\([^\)]*\))",
    ]
    xss_regex = re.compile("|".join(xss_patterns), re.IGNORECASE)

    cmdi_patterns = [
        r"(;\s*(ls|cat|dir|id|whoami|uname|netstat|ps)\b)",
        r"(\|\s*(ls|cat|dir|id|whoami|uname|netstat|ps)\b)",
        r"(&&\s*(ls|cat|dir|id|whoami|uname|netstat|ps)\b)",
        r"(`\s*whoami\s*`|`\s*id\s*`)",
        r"(\$\(\s*(whoami|id|cat)\s*\))",
        r"(/etc/passwd|/etc/shadow)",
        r"(/bin/sh|/bin/bash)",
        r"(nc\s+-e\s+|bash\s+-i)",
        r"(wget\s+http|curl\s+http)",
    ]
    cmdi_regex = re.compile("|".join(cmdi_patterns), re.IGNORECASE)

    traversal_patterns = [
        r"(\.\./|\.\.\\)",
        r"(%2e%2e%2f|%2e%2e/|\.\.%2f)",
        r"(/etc/passwd|c:\\windows|c:/windows)",
        r"(/proc/self/|/var/log/)",
    ]
    traversal_regex = re.compile("|".join(traversal_patterns), re.IGNORECASE)

    sensitive_regex = re.compile("|".join(re.escape(s) for s in SENSITIVE_ENDPOINTS), re.IGNORECASE)

    def __init__(self, custom_settings: dict | None = None):
        self.settings = custom_settings or {}

    def _get_threshold(self, key: str, fallback):
        return self.settings.get(key, get_setting(key, fallback))

    def analyze(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Runs all rule checks on the DataFrame using vectorized pre-filtering.
        Returns a DataFrame of alerts.
        """
        if df is None or df.empty:
            return pd.DataFrame(columns=[
                "alert_id", "timestamp", "source_ip", "username",
                "alert_type", "severity", "status", "evidence",
                "recommended_action", "detection_method"
            ])

        # Precompute combined string payload once for all regex rules
        endpoint_str = df["endpoint"].astype(str)
        event_str = df["event_type"].astype(str)
        payload = (endpoint_str + " " + event_str).tolist()
        event_list = event_str.str.lower().tolist()

        alerts = []
        alerts.extend(self._detect_brute_force(df))
        alerts.extend(self._detect_sqli(df, payload, event_list))
        alerts.extend(self._detect_xss(df, payload, event_list))
        alerts.extend(self._detect_cmdi(df, payload, event_list))
        alerts.extend(self._detect_path_traversal(df, payload, event_list))
        alerts.extend(self._detect_high_volume(df))
        alerts.extend(self._detect_sensitive_endpoint_probing(df, endpoint_str))

        if not alerts:
            return pd.DataFrame(columns=[
                "alert_id", "timestamp", "source_ip", "username",
                "alert_type", "severity", "status", "evidence",
                "recommended_action", "detection_method"
            ])

        alert_df = pd.DataFrame(alerts)
        alert_df = alert_df.sort_values(by="timestamp", ascending=False).reset_index(drop=True)
        return alert_df

    def _detect_brute_force(self, df: pd.DataFrame) -> list[dict]:
        alerts = []
        bf_thresh = self._get_threshold("BRUTE_FORCE_THRESHOLD", BRUTE_FORCE_THRESHOLD)
        bf_crit = self._get_threshold("BRUTE_FORCE_CRITICAL", BRUTE_FORCE_CRITICAL)

        status_s = df["status"].astype(str).str.lower()
        event_s = df["event_type"].astype(str).str.lower()
        endpoint_s = df["endpoint"].astype(str).str.lower()

        is_failed = status_s.isin(["failed", "failure", "denied", "401", "403"])
        is_login = (event_s.str.contains("login|auth|signin", na=False) | 
                    endpoint_s.str.contains("login|auth|session", na=False))

        failed_logins = df[is_failed & is_login]

        if failed_logins.empty:
            return alerts

        counts = failed_logins["source_ip"].value_counts()
        offending_ips = counts[counts >= bf_thresh].index

        if offending_ips.empty:
            return alerts

        for ip in offending_ips:
            group = failed_logins[failed_logins["source_ip"] == ip]
            count = len(group)
            severity = "Critical" if count >= bf_crit else "High"
            targeted_users = list(group["username"].dropna().unique())
            users_str = ", ".join(targeted_users[:3])
            if len(targeted_users) > 3:
                users_str += f" (+{len(targeted_users)-3} more)"
            
            latest_ts = group["timestamp"].max()
            alerts.append({
                "alert_id": str(uuid.uuid4()),
                "timestamp": str(latest_ts),
                "source_ip": str(ip),
                "username": users_str or "unknown",
                "alert_type": "Brute Force Attempt",
                "severity": severity,
                "status": "New",
                "evidence": f"{count} failed authentication attempts recorded for accounts: [{users_str}]",
                "recommended_action": f"Block IP {ip} temporarily and enforce MFA on targeted account(s).",
                "detection_method": "Rule-Based (Threshold)"
            })

        return alerts

    def _detect_sqli(self, df: pd.DataFrame, payload_list: list[str], event_list: list[str]) -> list[dict]:
        alerts = []
        mask = [bool(self.sqli_regex.search(p) or "sql injection" in e) for p, e in zip(payload_list, event_list)]
        matched = df[mask]

        if matched.empty:
            return alerts

        for row in matched.itertuples(index=False):
            p_text = f"{row.endpoint} {row.event_type}"
            m = self.sqli_regex.search(p_text)
            pattern_found = m.group(0) if m else "SQL Injection keywords"
            alerts.append({
                "alert_id": str(uuid.uuid4()),
                "timestamp": str(row.timestamp),
                "source_ip": str(row.source_ip),
                "username": str(getattr(row, "username", "unknown")),
                "alert_type": "SQL Injection",
                "severity": "Critical" if any(k in pattern_found.lower() for k in ["union", "drop", "xp_"]) else "High",
                "status": "New",
                "evidence": f"SQL syntax anomaly: '{pattern_found}' in request target '{row.endpoint}'",
                "recommended_action": "Sanitize backend parameter binding and review database query logs.",
                "detection_method": "Rule-Based (Regex)"
            })
        return alerts

    def _detect_xss(self, df: pd.DataFrame, payload_list: list[str], event_list: list[str]) -> list[dict]:
        alerts = []
        if not self._get_threshold("XSS_DETECTION", True):
            return alerts

        mask = [bool(self.xss_regex.search(p) or "xss" in e) for p, e in zip(payload_list, event_list)]
        matched = df[mask]

        if matched.empty:
            return alerts

        for row in matched.itertuples(index=False):
            p_text = f"{row.endpoint} {row.event_type}"
            m = self.xss_regex.search(p_text)
            pattern_found = m.group(0) if m else "Script tags or JS event"
            alerts.append({
                "alert_id": str(uuid.uuid4()),
                "timestamp": str(row.timestamp),
                "source_ip": str(row.source_ip),
                "username": str(getattr(row, "username", "unknown")),
                "alert_type": "Cross-Site Scripting (XSS)",
                "severity": "High",
                "status": "New",
                "evidence": f"Unsanitized client script sequence: '{pattern_found}' in request endpoint",
                "recommended_action": "Implement Content Security Policy (CSP) and context-aware HTML entity encoding.",
                "detection_method": "Rule-Based (Signature)"
            })
        return alerts

    def _detect_cmdi(self, df: pd.DataFrame, payload_list: list[str], event_list: list[str]) -> list[dict]:
        alerts = []
        if not self._get_threshold("CMD_INJECTION_DETECTION", True):
            return alerts

        mask = [bool(self.cmdi_regex.search(p) or "command injection" in e) for p, e in zip(payload_list, event_list)]
        matched = df[mask]

        if matched.empty:
            return alerts

        for row in matched.itertuples(index=False):
            p_text = f"{row.endpoint} {row.event_type}"
            m = self.cmdi_regex.search(p_text)
            pattern_found = m.group(0) if m else "OS command meta-characters"
            alerts.append({
                "alert_id": str(uuid.uuid4()),
                "timestamp": str(row.timestamp),
                "source_ip": str(row.source_ip),
                "username": str(getattr(row, "username", "unknown")),
                "alert_type": "Command Injection",
                "severity": "Critical",
                "status": "New",
                "evidence": f"Operating system shell operator detected: '{pattern_found}'",
                "recommended_action": "Isolate the receiving container/host; disable shell execution wrappers in backend code.",
                "detection_method": "Rule-Based (Regex)"
            })
        return alerts

    def _detect_path_traversal(self, df: pd.DataFrame, payload_list: list[str], event_list: list[str]) -> list[dict]:
        alerts = []
        if not self._get_threshold("PATH_TRAVERSAL_DETECTION", True):
            return alerts

        mask = [bool(self.traversal_regex.search(p) or "path traversal" in e) for p, e in zip(payload_list, event_list)]
        matched = df[mask]

        if matched.empty:
            return alerts

        for row in matched.itertuples(index=False):
            p_text = f"{row.endpoint} {row.event_type}"
            m = self.traversal_regex.search(p_text)
            pattern_found = m.group(0) if m else "Relative path sequence (../)"
            alerts.append({
                "alert_id": str(uuid.uuid4()),
                "timestamp": str(row.timestamp),
                "source_ip": str(row.source_ip),
                "username": str(getattr(row, "username", "unknown")),
                "alert_type": "Path Traversal",
                "severity": "High",
                "status": "New",
                "evidence": f"Directory traversal indicator '{pattern_found}' in target endpoint '{row.endpoint}'",
                "recommended_action": "Canonicalize file access paths using strict chroot or whitelist directory paths.",
                "detection_method": "Rule-Based (Signature)"
            })
        return alerts

    def _detect_high_volume(self, df: pd.DataFrame) -> list[dict]:
        alerts = []
        high_vol_thresh = self._get_threshold("HIGH_VOLUME_THRESHOLD", HIGH_VOLUME_THRESHOLD)
        counts = df["source_ip"].value_counts()
        offenders = counts[counts >= high_vol_thresh]
        
        if offenders.empty:
            return alerts

        for ip, count in offenders.items():
            ip_events = df[df["source_ip"] == ip]
            latest_ts = ip_events["timestamp"].max()
            alerts.append({
                "alert_id": str(uuid.uuid4()),
                "timestamp": str(latest_ts),
                "source_ip": str(ip),
                "username": "multiple",
                "alert_type": "High Request Volume",
                "severity": "Medium",
                "status": "New",
                "evidence": f"Abnormal event density: {count} HTTP transactions recorded from this host in dataset",
                "recommended_action": "Apply edge token-bucket rate limiting or temporary challenge on IP.",
                "detection_method": "Rule-Based (Volumetric)"
            })
        return alerts

    def _detect_sensitive_endpoint_probing(self, df: pd.DataFrame, endpoint_str: pd.Series) -> list[dict]:
        alerts = []
        ep_mask = endpoint_str.str.contains(self.sensitive_regex, na=False)
        status_s = df["status"].astype(str).str.lower()
        user_s = df["username"].astype(str).str.lower()

        status_mask = status_s.isin(["blocked", "denied", "failed", "403", "401"]) | user_s.isin(["unknown", "attacker", "root"])
        matched = df[ep_mask & status_mask]

        if matched.empty:
            return alerts

        for row in matched.itertuples(index=False):
            ep = str(row.endpoint)
            m = self.sensitive_regex.search(ep)
            matched_ep = m.group(0) if m else ep
            status = str(row.status)
            alerts.append({
                "alert_id": str(uuid.uuid4()),
                "timestamp": str(row.timestamp),
                "source_ip": str(row.source_ip),
                "username": str(getattr(row, "username", "unknown")),
                "alert_type": "Unusual Access Pattern",
                "severity": "Medium",
                "status": "New",
                "evidence": f"Probing privileged control endpoint: '{matched_ep}' with status '{status}'",
                "recommended_action": "Restrict administrative surfaces to private subnet or VPN access only.",
                "detection_method": "Rule-Based (Heuristic)"
            })
        return alerts
