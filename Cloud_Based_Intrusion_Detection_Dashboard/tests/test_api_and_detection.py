import sys
from pathlib import Path
import pytest
import pandas as pd
from fastapi.testclient import TestClient

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.main import app
from app.detection.rule_engine import RuleEngine
from app.detection.ml_detector import MLAnomalyDetector
from app.detection.ip_analyzer import IPAnalyzer
from app.detection.risk_calculator import RiskCalculator
from app.services.log_processor import log_processor
from app.database.db_service import db_service

client = TestClient(app)

def test_root_endpoint():
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert "Cloud-Based" in data["app"]

def test_cloud_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert "services" in data
    assert len(data["services"]) >= 4

def test_brute_force_detection():
    engine = RuleEngine()
    data = {
        "timestamp": [f"2026-11-20 01:00:{i:02d}" for i in range(12)],
        "source_ip": ["192.168.1.105"] * 12,
        "username": [f"user_{i}" for i in range(12)],
        "event_type": ["login"] * 12,
        "status": ["failed"] * 12,
        "endpoint": ["/login"] * 12
    }
    df = pd.DataFrame(data)
    alerts = engine.analyze(df)
    assert len(alerts) >= 1
    assert any(a["alert_type"] == "Brute Force Attempt" for a in alerts)
    assert any(a["severity"] == "Critical" for a in alerts)

def test_sqli_detection():
    engine = RuleEngine()
    data = {
        "timestamp": ["2026-11-20 02:30:15"],
        "source_ip": ["103.21.45.67"],
        "username": ["unknown"],
        "event_type": ["SQL Injection attempt"],
        "status": ["blocked"],
        "endpoint": ["/search?query=1' UNION SELECT username,password FROM users--"]
    }
    df = pd.DataFrame(data)
    alerts = engine.analyze(df)
    assert len(alerts) >= 1
    assert any("SQL Injection" in a["alert_type"] for a in alerts)
    assert alerts[0]["severity"] == "Critical"

def test_xss_detection():
    engine = RuleEngine()
    data = {
        "timestamp": ["2026-11-20 03:10:00"],
        "source_ip": ["172.16.0.44"],
        "username": ["attacker"],
        "event_type": ["page_post"],
        "status": ["blocked"],
        "endpoint": ["/comment?msg=<script>alert('xss')</script>"]
    }
    df = pd.DataFrame(data)
    alerts = engine.analyze(df)
    assert len(alerts) >= 1
    assert any(a["alert_type"] == "Cross-Site Scripting" for a in alerts)

def test_command_injection():
    engine = RuleEngine()
    data = {
        "timestamp": ["2026-11-20 04:15:00"],
        "source_ip": ["10.0.0.99"],
        "username": ["root"],
        "event_type": ["rce_attempt"],
        "status": ["blocked"],
        "endpoint": ["/api/ping?host=127.0.0.1; cat /etc/passwd"]
    }
    df = pd.DataFrame(data)
    alerts = engine.analyze(df)
    assert len(alerts) >= 1
    assert any(a["alert_type"] == "Command Injection" for a in alerts)
    assert alerts[0]["severity"] == "Critical"

def test_path_traversal():
    engine = RuleEngine()
    data = {
        "timestamp": ["2026-11-20 05:20:00"],
        "source_ip": ["10.0.0.99"],
        "username": ["guest"],
        "event_type": ["download"],
        "status": ["denied"],
        "endpoint": ["/files/view?path=../../etc/shadow"]
    }
    df = pd.DataFrame(data)
    alerts = engine.analyze(df)
    assert len(alerts) >= 1
    assert any(a["alert_type"] == "Path Traversal" for a in alerts)

def test_normal_traffic_no_false_positives():
    engine = RuleEngine()
    data = {
        "timestamp": ["2026-11-20 00:05:12", "2026-11-20 00:08:24"],
        "source_ip": ["192.168.1.10", "192.168.1.10"],
        "username": ["alice", "alice"],
        "event_type": ["login", "page_view"],
        "status": ["success", "success"],
        "endpoint": ["/login", "/dashboard"]
    }
    df = pd.DataFrame(data)
    alerts = engine.analyze(df)
    assert len(alerts) == 0

def test_log_validation_missing_columns():
    csv_bytes = b"wrong_col_1,wrong_col_2\nval1,val2"
    df, validation = log_processor.parse_file(csv_bytes, "test_bad.csv")
    assert not validation["valid"]
    assert len(validation["errors"]) > 0

def test_log_validation_duplicates_and_invalid_ips():
    csv_bytes = b"""timestamp,source_ip,username,event_type,status,endpoint
2026-11-20 00:01:00,999.999.999.999,bob,login,failed,/login
2026-11-20 00:01:00,999.999.999.999,bob,login,failed,/login
"""
    df, validation = log_processor.parse_file(csv_bytes, "test_invalid.csv")
    assert any("duplicate" in w.lower() for w in validation["warnings"])
    assert any("invalid ip" in w.lower() for w in validation["warnings"])

def test_dashboard_overview():
    res = client.get("/api/dashboard/overview")
    assert res.status_code == 200
    data = res.json()
    assert "metrics" in data
    assert "risk_indicator" in data
    assert "activity_timeline" in data
    assert "attack_distribution" in data
    assert "top_attacking_ips" in data
    assert "recent_alerts" in data

def test_threats_list_and_filter():
    res = client.get("/api/threats")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data

def test_ip_intelligence():
    res = client.get("/api/ip-intelligence")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data

def test_alert_status_update():
    # Insert an alert first
    test_alert = {
        "id": "alert-test-status-01",
        "timestamp": "2026-11-20 12:00:00",
        "source_ip": "192.168.1.200",
        "username": "tester",
        "alert_type": "Test Threat",
        "severity": "Medium",
        "status": "New",
        "description": "Test alert for status update verification",
        "evidence": "Evidence string",
        "risk_score": 60
    }
    db_service.save_alerts([test_alert])

    # Update to Investigating
    patch_res = client.patch(f"/api/alerts/{test_alert['id']}/status", json={"status": "Investigating"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "Investigating"

    # Update to Resolved
    patch_res2 = client.patch(f"/api/alerts/{test_alert['id']}/status", json={"status": "Resolved"})
    assert patch_res2.status_code == 200
    assert patch_res2.json()["status"] == "Resolved"

def test_report_generation():
    res = client.post("/api/reports/generate")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "report" in data
    assert data["report"]["filename"].endswith(".pdf")
