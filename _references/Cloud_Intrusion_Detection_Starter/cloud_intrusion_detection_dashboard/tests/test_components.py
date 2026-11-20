"""
Unit tests for IPAnalyzer, RiskCalculator, LocalDatabase, and SecurityReportGenerator.
"""
import os
import pandas as pd
from core.ip_analyzer import IPAnalyzer
from core.risk_calculator import RiskCalculator
from database.local_db import LocalDatabase
from utils.report_generator import SecurityReportGenerator

def test_ip_analyzer_classification():
    analyzer = IPAnalyzer()
    assert "Private" in analyzer.classify_ip("192.168.1.1")
    assert "Private" in analyzer.classify_ip("10.0.0.1")
    assert "Loopback" in analyzer.classify_ip("127.0.0.1")
    assert "Public" in analyzer.classify_ip("8.8.8.8")
    assert "Invalid" in analyzer.classify_ip("999.999.999.999")

def test_ip_analyzer_dossier():
    analyzer = IPAnalyzer()
    logs_df = pd.DataFrame([
        {
            "timestamp": "2026-11-20 10:00:00",
            "source_ip": "103.21.45.67",
            "username": "attacker",
            "event_type": "query",
            "status": "failed",
            "endpoint": "/search?id=1"
        }
    ])
    alerts_df = pd.DataFrame([
        {
            "alert_id": "test-123",
            "timestamp": "2026-11-20 10:00:00",
            "source_ip": "103.21.45.67",
            "username": "attacker",
            "alert_type": "SQL Injection",
            "severity": "Critical",
            "status": "New",
            "evidence": "Matched UNION SELECT",
            "recommended_action": "Sanitize query",
            "detection_method": "Rule Engine"
        }
    ])
    dossier = analyzer.analyze_ip("103.21.45.67", logs_df, alerts_df)
    assert dossier["found"] is True
    assert dossier["total_events"] == 1
    assert dossier["alert_count"] == 1
    assert dossier["risk_level"] in ["Critical", "High"]
    assert dossier["risk_score"] > 50

def test_risk_calculator():
    calc = RiskCalculator()
    empty_risk = calc.calculate_overall_risk(pd.DataFrame(), pd.DataFrame())
    assert "LOW" in empty_risk["level"]

    alerts_df = pd.DataFrame([
        {"severity": "Critical", "source_ip": "103.21.45.67", "alert_type": "SQL Injection"},
        {"severity": "Critical", "source_ip": "192.168.1.105", "alert_type": "Brute Force Attempt"}
    ])
    high_risk = calc.calculate_overall_risk(alerts_df, pd.DataFrame())
    assert "CRITICAL" in high_risk["level"]
    assert high_risk["percentage"] >= 75

    recs = calc.generate_recommendations(alerts_df, pd.DataFrame())
    assert len(recs) >= 2
    assert any("Brute Force" in r for r in recs)
    assert any("SQL Injection" in r for r in recs)

def test_local_database_lifecycle(tmp_path):
    db_file = str(tmp_path / "test_soc.db")
    db = LocalDatabase(db_file)
    
    alerts_df = pd.DataFrame([
        {
            "alert_id": "alert-abc",
            "timestamp": "2026-11-20 12:00:00",
            "source_ip": "192.168.1.100",
            "alert_type": "Brute Force",
            "severity": "High",
            "status": "New",
            "evidence": "5 failed logins",
            "username": "admin"
        }
    ])
    db.save_alerts(alerts_df)
    
    loaded = db.get_alerts()
    assert len(loaded) == 1
    assert loaded[0]["source_ip"] == "192.168.1.100"
    assert loaded[0]["status"] == "New"
    
    # Mutate status
    db.update_alert_status("alert-abc", "Investigating")
    updated = db.get_alerts()
    assert updated[0]["status"] == "Investigating"
    
    counts = db.get_alert_counts()
    assert counts.get("Investigating", 0) == 1
    
    db.close()

def test_pdf_report_generation():
    generator = SecurityReportGenerator()
    data = {
        "report_title": "Test SOC Report",
        "report_date": "2026-11-20 20:00:00",
        "total_events": 150,
        "threats_detected": 12,
        "suspicious_ips": 4,
        "blocked_attempts": 25,
        "risk_assessment": {"level": "HIGH RISK", "percentage": 85, "color": "#FF4560"},
        "severity_counts": {"Critical": 3, "High": 5, "Medium": 4, "Low": 0},
        "attack_categories": {"Brute Force": 5, "SQL Injection": 4, "XSS": 3},
        "top_suspicious_ips": [{"source_ip": "103.21.45.67", "count": 4, "severity": "Critical"}],
        "recommendations": ["Enforce IP rate limiting", "Lock accounts after 5 failures"]
    }
    pdf_bytes = generator.generate_report(data)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")

def test_cached_chart_generators():
    from pages.attack_analytics import (
        get_attack_vector_fig,
        get_hourly_activity_fig,
        get_top_endpoints_fig,
        get_auth_verdict_fig,
        get_dow_trend_fig,
        get_severity_fig,
    )
    from pages.ip_intelligence import get_ip_timeline_fig

    sample_alerts = pd.DataFrame([
        {"alert_type": "SQL Injection", "timestamp": "2026-11-20 10:15:00", "severity": "High"},
        {"alert_type": "Brute Force", "timestamp": "2026-11-20 10:20:00", "severity": "Critical"}
    ])
    sample_logs = pd.DataFrame([
        {"endpoint": "/login", "status": "failed", "timestamp_dt": pd.to_datetime("2026-11-20 10:00:00")},
        {"endpoint": "/search", "status": "200", "timestamp_dt": pd.to_datetime("2026-11-20 10:30:00")}
    ])

    # Ensure all chart generators produce valid plotly figures
    assert get_attack_vector_fig(sample_alerts) is not None
    assert get_hourly_activity_fig(sample_alerts) is not None
    assert get_dow_trend_fig(sample_alerts) is not None
    assert get_severity_fig(sample_alerts) is not None
    assert get_top_endpoints_fig(sample_logs) is not None
    assert get_auth_verdict_fig(sample_logs) is not None
    assert get_ip_timeline_fig(sample_logs) is not None

    # Ensure empty inputs return None gracefully
    assert get_attack_vector_fig(pd.DataFrame()) is None
    assert get_ip_timeline_fig(pd.DataFrame()) is None
