import random
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
import pandas as pd

from app.detection.rule_engine import RuleEngine
from app.detection.ip_analyzer import IPAnalyzer
from app.database.db_service import db_service

class LiveEventSimulator:
    """
    Simulates real-time security telemetry ingestion for demonstration and testing.
    Clearly labeled as SIMULATED telemetric traffic.
    """

    KNOWN_IPS = [
        "192.168.1.105", "103.21.45.67", "172.16.0.23",
        "45.77.89.12", "91.203.12.78", "192.168.1.10",
        "10.0.0.45", "185.220.101.5", "192.168.1.22"
    ]

    EVENT_TEMPLATES = [
        # Normal events
        {"event_type": "login", "status": "success", "endpoint": "/login", "user": "alice", "is_attack": False},
        {"event_type": "api_query", "status": "success", "endpoint": "/api/v1/metrics", "user": "bob", "is_attack": False},
        {"event_type": "page_view", "status": "success", "endpoint": "/dashboard", "user": "charlie", "is_attack": False},
        {"event_type": "download", "status": "success", "endpoint": "/files/report.pdf", "user": "diana", "is_attack": False},
        # Attack events
        {"event_type": "login", "status": "failed", "endpoint": "/login", "user": "admin", "is_attack": True, "type": "brute_force"},
        {"event_type": "SQL Injection attempt", "status": "blocked", "endpoint": "/search?query=1' UNION SELECT user,pass FROM accounts--", "user": "unknown", "is_attack": True, "type": "sqli"},
        {"event_type": "XSS attempt", "status": "blocked", "endpoint": "/comments?msg=<script>alert('pwned')</script>", "user": "anonymous", "is_attack": True, "type": "xss"},
        {"event_type": "unusual_probe", "status": "blocked", "endpoint": "/admin/config.php", "user": "anonymous", "is_attack": True, "type": "probe"},
        {"event_type": "traversal_attempt", "status": "denied", "endpoint": "/download?file=../../etc/passwd", "user": "unknown", "is_attack": True, "type": "traversal"},
    ]

    def __init__(self):
        self.rule_engine = RuleEngine()
        self.ip_analyzer = IPAnalyzer()

    def generate_event(self) -> Dict[str, Any]:
        """Generates a single simulated telemetry log event."""
        template = random.choice(self.EVENT_TEMPLATES)
        ip = random.choice(self.KNOWN_IPS)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        event = {
            "id": f"sim-{uuid.uuid4().hex[:8]}",
            "timestamp": now,
            "source_ip": ip,
            "username": template["user"],
            "event_type": template["event_type"],
            "status": template["status"],
            "endpoint": template["endpoint"],
            "classification": template.get("type", "Normal") if template["is_attack"] else "Normal",
            "risk_score": 85 if template["is_attack"] else 0
        }

        # Store to DB
        db_service.save_logs([event])

        # If attack, generate matching alert
        alert = None
        if template["is_attack"]:
            alert_type_map = {
                "brute_force": ("Brute Force Attempt", "High", "Repeated failed authentication event."),
                "sqli": ("SQL Injection Attempt", "Critical", "Injected UNION SELECT command pattern in URL parameter."),
                "xss": ("Cross-Site Scripting", "High", "JavaScript script tag execution payload."),
                "probe": ("Sensitive Endpoint Probing", "Medium", "Reconnaissance scan targeting internal admin paths."),
                "traversal": ("Path Traversal", "High", "Directory climbing pattern ../../etc/passwd identified.")
            }
            atype, sev, desc = alert_type_map.get(template["type"], ("Suspicious Activity", "Medium", "Anomalous event pattern."))
            alert = {
                "id": f"alert-sim-{uuid.uuid4().hex[:8]}",
                "timestamp": now,
                "source_ip": ip,
                "username": template["user"],
                "alert_type": atype,
                "severity": sev,
                "status": "New",
                "description": desc,
                "evidence": f"Endpoint: {template['endpoint']} (Status: {template['status']})",
                "recommended_action": "Investigate source IP telemetry and apply adaptive firewall inspection.",
                "detection_method": "simulated-live-stream",
                "risk_score": 90 if sev == "Critical" else (75 if sev == "High" else 50)
            }
            db_service.save_alerts([alert])

        return {"event": event, "alert": alert}

    def generate_batch(self, count: int = 5) -> List[Dict[str, Any]]:
        results = []
        for _ in range(count):
            results.append(self.generate_event())
        return results

live_simulator = LiveEventSimulator()
