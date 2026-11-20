"""
Unit tests for LogProcessor: ingestion, enrichment, and dataset summary.
"""
import pandas as pd
from core.log_processor import LogProcessor

def test_enrich_logs():
    processor = LogProcessor()
    df = pd.DataFrame([
        {
            "timestamp": "2026-11-20 14:30:00",
            "source_ip": "192.168.1.10",
            "username": "alice",
            "event_type": "login",
            "status": "failed",
            "endpoint": "/login"
        },
        {
            "timestamp": "2026-11-20 15:00:00",
            "source_ip": "10.0.0.5",
            "username": "bob",
            "event_type": "page_view",
            "status": "blocked",
            "endpoint": "/admin/config"
        }
    ])
    enriched = processor.enrich_logs(df)
    assert "hour" in enriched.columns
    assert enriched["hour"].iloc[0] == 14
    assert bool(enriched["is_failed"].iloc[0]) is True
    assert bool(enriched["is_blocked"].iloc[1]) is True
    assert enriched["endpoint_category"].iloc[0] == "Authentication"
    assert enriched["endpoint_category"].iloc[1] == "Administrative"

def test_dataset_summary():
    processor = LogProcessor()
    df = pd.DataFrame([
        {
            "timestamp": "2026-11-20 10:00:00",
            "source_ip": "192.168.1.1",
            "username": "user1",
            "event_type": "login",
            "status": "success",
            "endpoint": "/home"
        },
        {
            "timestamp": "2026-11-20 11:00:00",
            "source_ip": "192.168.1.2",
            "username": "user2",
            "event_type": "api",
            "status": "blocked",
            "endpoint": "/api"
        }
    ])
    summary = processor.get_dataset_summary(df)
    assert summary["total_records"] == 2
    assert summary["unique_ips"] == 2
    assert summary["blocked_attempts"] == 1
    assert summary["success_attempts"] == 1
