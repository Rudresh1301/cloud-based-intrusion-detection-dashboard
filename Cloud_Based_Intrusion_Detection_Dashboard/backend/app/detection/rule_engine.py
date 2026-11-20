import re
import uuid
from typing import List, Dict, Any, Optional
import pandas as pd
from app.core.config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_CRITICAL,
    HIGH_VOLUME_THRESHOLD,
    SENSITIVE_ENDPOINTS,
)

class RuleEngine:
    """
    Deterministic Threat Detection Heuristics Engine.
    Executes vectorized regex scanning and stateful grouping for:
    - Brute Force Login Attacks
    - SQL Injection (SQLi)
    - Cross-Site Scripting (XSS)
    - Command Injection (RCE)
    - Path Traversal (LFI/RFI)
    - High Request Flooding
    - Sensitive Endpoint Probing
    """

    # Precompile regex signatures for speed
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

    def __init__(self, custom_thresholds: Optional[Dict[str, Any]] = None):
        self.thresholds = custom_thresholds or {}

    def _get_thresh(self, key: str, fallback: int) -> int:
        return int(self.thresholds.get(key, fallback))

    def analyze(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Evaluates DataFrame of log records against all deterministic heuristics."""
        if df is None or df.empty:
            return []

        alerts: List[Dict[str, Any]] = []

        endpoint_str = df["endpoint"].astype(str)
        event_str = df["event_type"].astype(str)
        payload = (endpoint_str + " " + event_str).tolist()
        event_list = event_str.str.lower().tolist()

        alerts.extend(self._detect_brute_force(df))
        alerts.extend(self._detect_sqli(df, payload, event_list))
        alerts.extend(self._detect_xss(df, payload, event_list))
        alerts.extend(self._detect_cmdi(df, payload, event_list))
        alerts.extend(self._detect_path_traversal(df, payload, event_list))
        alerts.extend(self._detect_high_volume(df))
        alerts.extend(self._detect_sensitive_probes(df, endpoint_str))

        # Sort alerts descending by timestamp
        alerts.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
        return alerts

    def _detect_brute_force(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        bf_thresh = self._get_thresh("brute_force_threshold", BRUTE_FORCE_THRESHOLD)
        bf_crit = self._get_thresh("brute_force_critical", BRUTE_FORCE_CRITICAL)

        status_s = df["status"].astype(str).str.lower()
        event_s = df["event_type"].astype(str).str.lower()
        endpoint_s = df["endpoint"].astype(str).str.lower()

        is_failed = status_s.isin(["failed", "failure", "denied", "401", "403", "blocked"])
        is_login = (event_s.str.contains("login|auth|signin|password", na=False) | 
                    endpoint_s.str.contains("login|auth|session|token", na=False))

        failed_logins = df[is_failed & is_login]
        if failed_logins.empty:
            return alerts

        for ip, grp in failed_logins.groupby("source_ip"):
            count = len(grp)
            if count >= bf_thresh:
                severity = "Critical" if count >= bf_crit else "High"
                risk_score = 95 if count >= bf_crit else 80
                users = list(grp["username"].dropna().unique())
                user_str = ", ".join(users[:4]) if users else "various accounts"
                last_event = grp.iloc[-1]

                alerts.append({
                    "id": f"alert-bf-{uuid.uuid4().hex[:8]}",
                    "timestamp": str(last_event["timestamp"]),
                    "source_ip": str(ip),
                    "username": str(last_event.get("username", "multiple")),
                    "alert_type": "Brute Force Attempt",
                    "severity": severity,
                    "status": "New",
                    "description": f"Detected {count} rapid consecutive failed authentication attempts targeting {user_str}.",
                    "evidence": f"{count} failed login requests against {last_event['endpoint']}",
                    "recommended_action": f"Apply immediate IP firewall rate-limiting or temporary block on {ip}; audit targeted accounts for lockouts.",
                    "detection_method": "rule-based",
                    "risk_score": risk_score
                })
        return alerts

    def _detect_sqli(self, df: pd.DataFrame, payload: List[str], event_list: List[str]) -> List[Dict[str, Any]]:
        alerts = []
        for idx, row in df.iterrows():
            text = payload[idx]
            match = self.sqli_regex.search(text) or "sql" in event_list[idx]
            if match:
                evidence = match.group(0) if hasattr(match, 'group') else str(row["endpoint"])
                alerts.append({
                    "id": f"alert-sqli-{uuid.uuid4().hex[:8]}",
                    "timestamp": str(row["timestamp"]),
                    "source_ip": str(row["source_ip"]),
                    "username": str(row.get("username", "unknown")),
                    "alert_type": "SQL Injection Attempt",
                    "severity": "Critical",
                    "status": "New",
                    "description": f"SQL syntax manipulation pattern detected in request parameter: '{evidence}'.",
                    "evidence": f"Endpoint: {row['endpoint']} (Pattern: {evidence})",
                    "recommended_action": "Verify parameterized queries / ORM prepared statements; enforce Web Application Firewall (WAF) SQLi inspection.",
                    "detection_method": "rule-based",
                    "risk_score": 90
                })
        return alerts

    def _detect_xss(self, df: pd.DataFrame, payload: List[str], event_list: List[str]) -> List[Dict[str, Any]]:
        alerts = []
        for idx, row in df.iterrows():
            text = payload[idx]
            match = self.xss_regex.search(text) or "xss" in event_list[idx]
            if match:
                evidence = match.group(0) if hasattr(match, 'group') else str(row["endpoint"])
                alerts.append({
                    "id": f"alert-xss-{uuid.uuid4().hex[:8]}",
                    "timestamp": str(row["timestamp"]),
                    "source_ip": str(row["source_ip"]),
                    "username": str(row.get("username", "unknown")),
                    "alert_type": "Cross-Site Scripting",
                    "severity": "High",
                    "status": "New",
                    "description": f"Malicious script injection attempt detected in request payload: '{evidence}'.",
                    "evidence": f"Endpoint: {row['endpoint']} (Pattern: {evidence})",
                    "recommended_action": "Implement context-aware HTML entity escaping; enforce strict Content Security Policy (CSP) headers.",
                    "detection_method": "rule-based",
                    "risk_score": 75
                })
        return alerts

    def _detect_cmdi(self, df: pd.DataFrame, payload: List[str], event_list: List[str]) -> List[Dict[str, Any]]:
        alerts = []
        for idx, row in df.iterrows():
            text = payload[idx]
            match = self.cmdi_regex.search(text) or "command" in event_list[idx] or "rce" in event_list[idx]
            if match:
                evidence = match.group(0) if hasattr(match, 'group') else str(row["endpoint"])
                alerts.append({
                    "id": f"alert-cmdi-{uuid.uuid4().hex[:8]}",
                    "timestamp": str(row["timestamp"]),
                    "source_ip": str(row["source_ip"]),
                    "username": str(row.get("username", "unknown")),
                    "alert_type": "Command Injection",
                    "severity": "Critical",
                    "status": "New",
                    "description": f"Operating system shell command execution pattern identified: '{evidence}'.",
                    "evidence": f"Endpoint: {row['endpoint']} (Pattern: {evidence})",
                    "recommended_action": "Sanitize shell inputs; eliminate system/exec shell subprocess invocations; isolate host privileges.",
                    "detection_method": "rule-based",
                    "risk_score": 98
                })
        return alerts

    def _detect_path_traversal(self, df: pd.DataFrame, payload: List[str], event_list: List[str]) -> List[Dict[str, Any]]:
        alerts = []
        for idx, row in df.iterrows():
            text = payload[idx]
            match = self.traversal_regex.search(text) or "traversal" in event_list[idx]
            if match:
                evidence = match.group(0) if hasattr(match, 'group') else str(row["endpoint"])
                alerts.append({
                    "id": f"alert-pt-{uuid.uuid4().hex[:8]}",
                    "timestamp": str(row["timestamp"]),
                    "source_ip": str(row["source_ip"]),
                    "username": str(row.get("username", "unknown")),
                    "alert_type": "Path Traversal",
                    "severity": "High",
                    "status": "New",
                    "description": f"Directory escape sequence detected in path parameters: '{evidence}'.",
                    "evidence": f"Endpoint: {row['endpoint']} (Pattern: {evidence})",
                    "recommended_action": "Use strict path canonicalization and whitelist allowed base storage directories.",
                    "detection_method": "rule-based",
                    "risk_score": 80
                })
        return alerts

    def _detect_high_volume(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        volume_thresh = self._get_thresh("high_volume_threshold", HIGH_VOLUME_THRESHOLD)
        for ip, grp in df.groupby("source_ip"):
            count = len(grp)
            if count >= volume_thresh:
                last_event = grp.iloc[-1]
                alerts.append({
                    "id": f"alert-flood-{uuid.uuid4().hex[:8]}",
                    "timestamp": str(last_event["timestamp"]),
                    "source_ip": str(ip),
                    "username": str(last_event.get("username", "anonymous")),
                    "alert_type": "Unusual Traffic Flooding",
                    "severity": "Medium",
                    "status": "New",
                    "description": f"High request frequency observed: {count} transactions from single source host.",
                    "evidence": f"{count} total requests in batch log window",
                    "recommended_action": "Deploy cloud reverse-proxy throttling / CDN rate limiting.",
                    "detection_method": "rule-based",
                    "risk_score": 60
                })
        return alerts

    def _detect_sensitive_probes(self, df: pd.DataFrame, endpoint_str: pd.Series) -> List[Dict[str, Any]]:
        alerts = []
        for idx, row in df.iterrows():
            ep = endpoint_str.iloc[idx]
            status_low = str(row["status"]).lower()
            if self.sensitive_regex.search(ep) and status_low in ["blocked", "denied", "401", "403", "404", "failed"]:
                alerts.append({
                    "id": f"alert-probe-{uuid.uuid4().hex[:8]}",
                    "timestamp": str(row["timestamp"]),
                    "source_ip": str(row["source_ip"]),
                    "username": str(row.get("username", "anonymous")),
                    "alert_type": "Sensitive Endpoint Probing",
                    "severity": "Medium",
                    "status": "New",
                    "description": f"Reconnaissance scan probing administrative interface '{ep}'.",
                    "evidence": f"Target: {ep} (Response: {row['status']})",
                    "recommended_action": "Restrict administrative URLs behind Cloud VPN / IP ACLs.",
                    "detection_method": "rule-based",
                    "risk_score": 55
                })
        return alerts
