"""
Unit tests for the Intrusion Detection Engine (RuleEngine, MLDetector, and IntrusionDetector).
"""
import pandas as pd
from core.rule_engine import RuleEngine
from core.detector import IntrusionDetector
from core.ml_detector import MLDetector

def test_detect_brute_force():
    engine = RuleEngine({"BRUTE_FORCE_THRESHOLD": 5, "BRUTE_FORCE_CRITICAL": 10})
    rows = []
    # 6 failed logins from one IP
    for i in range(6):
        rows.append({
            "timestamp": f"2026-11-20 08:00:0{i}",
            "source_ip": "203.0.113.45",
            "username": "admin",
            "event_type": "login",
            "status": "failed",
            "endpoint": "/login"
        })
    df = pd.DataFrame(rows)
    alerts = engine.analyze(df)
    assert not alerts.empty
    bf_alerts = alerts[alerts["alert_type"] == "Brute Force Attempt"]
    assert len(bf_alerts) == 1
    assert bf_alerts.iloc[0]["severity"] == "High"
    assert bf_alerts.iloc[0]["source_ip"] == "203.0.113.45"

def test_detect_sqli():
    engine = RuleEngine()
    df = pd.DataFrame([
        {
            "timestamp": "2026-11-20 08:00:00",
            "source_ip": "103.21.45.67",
            "username": "guest",
            "event_type": "search",
            "status": "blocked",
            "endpoint": "/products?id=1 UNION SELECT password FROM users--"
        }
    ])
    alerts = engine.analyze(df)
    assert not alerts.empty
    sqli = alerts[alerts["alert_type"] == "SQL Injection"]
    assert len(sqli) == 1
    assert sqli.iloc[0]["severity"] == "Critical"

def test_detect_xss():
    engine = RuleEngine({"XSS_DETECTION": True})
    df = pd.DataFrame([
        {
            "timestamp": "2026-11-20 08:00:00",
            "source_ip": "91.203.12.78",
            "username": "guest",
            "event_type": "comment",
            "status": "blocked",
            "endpoint": "/post?comment=<script>alert('xss')</script>"
        }
    ])
    alerts = engine.analyze(df)
    assert not alerts.empty
    xss = alerts[alerts["alert_type"] == "Cross-Site Scripting (XSS)"]
    assert len(xss) == 1

def test_detect_path_traversal():
    engine = RuleEngine({"PATH_TRAVERSAL_DETECTION": True})
    df = pd.DataFrame([
        {
            "timestamp": "2026-11-20 08:00:00",
            "source_ip": "185.220.101.33",
            "username": "unknown",
            "event_type": "download",
            "status": "blocked",
            "endpoint": "/files?doc=../../../../etc/passwd"
        }
    ])
    alerts = engine.analyze(df)
    assert not alerts.empty
    pt = alerts[alerts["alert_type"] == "Path Traversal"]
    assert len(pt) == 1

def test_detect_command_injection():
    engine = RuleEngine({"CMD_INJECTION_DETECTION": True})
    df = pd.DataFrame([
        {
            "timestamp": "2026-11-20 08:00:00",
            "source_ip": "185.220.101.33",
            "username": "unknown",
            "event_type": "ping",
            "status": "blocked",
            "endpoint": "/tools/ping?ip=127.0.0.1; whoami"
        }
    ])
    alerts = engine.analyze(df)
    assert not alerts.empty
    cmd = alerts[alerts["alert_type"] == "Command Injection"]
    assert len(cmd) == 1

def test_ml_anomaly_detector():
    ml = MLDetector()
    # Create sample dataset with multiple normal IPs and one extreme outlier
    records = []
    # 5 normal IPs
    for ip_suffix in range(1, 6):
        ip = f"192.168.1.{ip_suffix}"
        for _ in range(5):
            records.append({
                "timestamp": "2026-11-20 10:00:00",
                "source_ip": ip,
                "username": f"user{ip_suffix}",
                "event_type": "page_view",
                "status": "success",
                "endpoint": "/dashboard"
            })
    # 1 outlier IP with 100 requests, failed status, and injection payload
    for _ in range(60):
        records.append({
            "timestamp": "2026-11-20 10:00:00",
            "source_ip": "45.77.89.12",
            "username": "attacker",
            "event_type": "sql injection attempt",
            "status": "failed",
            "endpoint": "/search?id=1 UNION SELECT 1"
        })
    df = pd.DataFrame(records)
    res = ml.train_and_predict(df)
    assert res["success"] is True
    assert "features" in res
    assert "anomalies" in res
    # The outlier IP should be flagged as anomaly
    anom_ips = list(res["anomalies"]["source_ip"].unique())
    assert "45.77.89.12" in anom_ips

def test_full_pipeline_sample():
    detector = IntrusionDetector()
    df = pd.DataFrame([
        {
            "timestamp": "2026-11-20 08:00:00",
            "source_ip": "192.168.1.1",
            "username": "alice",
            "event_type": "login",
            "status": "success",
            "endpoint": "/login"
        },
        {
            "timestamp": "2026-11-20 08:01:00",
            "source_ip": "103.21.45.67",
            "username": "unknown",
            "event_type": "query",
            "status": "blocked",
            "endpoint": "/search?id=1 OR 1=1"
        }
    ])
    res = detector.analyze(df)
    assert "enriched_logs" in res
    assert "rule_alerts" in res
    assert "risk_assessment" in res
    assert "recommendations" in res
    assert len(res["rule_alerts"]) >= 1
