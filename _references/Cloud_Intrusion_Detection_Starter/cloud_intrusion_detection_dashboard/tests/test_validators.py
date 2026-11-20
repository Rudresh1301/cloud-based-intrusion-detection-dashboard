"""
Unit tests for data validation, cleaning and schema verification.
"""
import pandas as pd
from utils.validators import (
    validate_csv_upload,
    clean_dataframe,
    validate_ip_address,
    validate_timestamp,
)

def test_validate_ip_address():
    assert validate_ip_address("192.168.1.1") is True
    assert validate_ip_address("10.0.0.1") is True
    assert validate_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
    assert validate_ip_address("999.999.999.999") is False
    assert validate_ip_address("not_an_ip") is False
    assert validate_ip_address(None) is False

def test_validate_timestamp():
    assert validate_timestamp("2026-11-20 08:00:00") is True
    assert validate_timestamp("2026-11-20T08:00:00Z") is True
    assert validate_timestamp("invalid_date") is False
    assert validate_timestamp(None) is False

def test_validate_csv_upload_valid():
    df = pd.DataFrame([
        {
            "timestamp": "2026-11-20 10:00:00",
            "source_ip": "192.168.1.10",
            "username": "alice",
            "event_type": "login",
            "status": "success",
            "endpoint": "/login"
        }
    ])
    res = validate_csv_upload(df)
    assert res["valid"] is True
    assert len(res["errors"]) == 0
    assert res["stats"]["total_rows"] == 1

def test_validate_csv_upload_missing_columns():
    df = pd.DataFrame([{"wrong_col": 123}])
    res = validate_csv_upload(df)
    assert res["valid"] is False
    assert len(res["errors"]) > 0

def test_clean_dataframe():
    df = pd.DataFrame([
        {
            " timestamp ": "2026-11-20 10:00:00",
            "source_ip": " 192.168.1.10 ",
            "username": None,
            "event_type": "LOGIN",
            "status": "SUCCESS",
            "endpoint": " /login "
        }
    ])
    cleaned = clean_dataframe(df)
    assert "timestamp" in cleaned.columns
    assert cleaned["source_ip"].iloc[0] == "192.168.1.10"
    assert cleaned["username"].iloc[0] == "unknown"
    assert cleaned["status"].iloc[0] == "success"
    assert cleaned["endpoint"].iloc[0] == "/login"
