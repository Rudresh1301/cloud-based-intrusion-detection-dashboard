"""
Data validation and sanitation for log ingestion.
Handles schema checking, type safety, dirty input cleaning, and stats computation.
"""
import ipaddress
import pandas as pd
from datetime import datetime
from config.settings import REQUIRED_COLUMNS

def validate_timestamp(ts_val) -> bool:
    """Checks whether a value can be parsed into a valid datetime."""
    if pd.isna(ts_val) or ts_val is None:
        return False
    try:
        pd.to_datetime(ts_val)
        return True
    except Exception:
        return False

def validate_ip_address(ip_val) -> bool:
    """Validates IPv4 or IPv6 syntax."""
    if pd.isna(ip_val) or not ip_val:
        return False
    try:
        ipaddress.ip_address(str(ip_val).strip())
        return True
    except ValueError:
        return False

def validate_csv_upload(df: pd.DataFrame) -> dict:
    """
    Validates uploaded DataFrame against required security log schema.
    Returns:
        dict: {
            "valid": bool,
            "errors": list[str],
            "warnings": list[str],
            "stats": dict
        }
    """
    errors = []
    warnings = []
    
    if df is None or not isinstance(df, pd.DataFrame) or df.empty:
        return {
            "valid": False,
            "errors": ["Uploaded file is completely empty or cannot be read as a table."],
            "warnings": [],
            "stats": {"total_rows": 0, "valid_rows": 0, "invalid_rows": 0, "duplicate_rows": 0}
        }

    # Column requirement check
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        errors.append(f"Missing mandatory column(s): {', '.join(sorted(missing))}. Required: {', '.join(REQUIRED_COLUMNS)}")

    total_rows = len(df)
    duplicate_rows = int(df.duplicated().sum())
    if duplicate_rows > 0:
        warnings.append(f"Found {duplicate_rows} duplicate record(s) in upload.")

    invalid_timestamps = 0
    invalid_ips = 0

    if "timestamp" in df.columns:
        parsed_ts = pd.to_datetime(df["timestamp"], errors="coerce")
        invalid_timestamps = int(parsed_ts.isna().sum())
        if invalid_timestamps > 0:
            warnings.append(f"{invalid_timestamps} record(s) contain unparseable or null timestamps.")

    if "source_ip" in df.columns:
        # Check invalid IP formats on unique set for 1000x faster validation on large logs
        unique_ips = df["source_ip"].dropna().unique()
        invalid_ip_set = {ip for ip in unique_ips if not validate_ip_address(ip)}
        if invalid_ip_set:
            invalid_ips = int(df["source_ip"].isin(invalid_ip_set).sum())
            warnings.append(f"{invalid_ips} record(s) have unrecognised or invalid IP formats.")
        else:
            invalid_ips = 0

    valid_rows = max(0, total_rows - invalid_timestamps)

    is_valid = len(errors) == 0

    stats = {
        "total_rows": total_rows,
        "valid_rows": valid_rows,
        "invalid_rows": invalid_timestamps,
        "duplicate_rows": duplicate_rows,
        "invalid_ips": invalid_ips,
        "columns_found": list(df.columns)
    }

    return {
        "valid": is_valid,
        "errors": errors,
        "warnings": warnings,
        "stats": stats
    }

def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans dirty log data without losing valid records:
    - Strips whitespace
    - Normalizes lowercase string columns where appropriate
    - Standardizes timestamps
    - Fills missing values with standard sentinels
    """
    cleaned = df.copy()
    
    # Strip whitespace from column headers
    cleaned.columns = [c.strip() for c in cleaned.columns]

    # Standardize string fields
    string_cols = ["source_ip", "username", "event_type", "status", "endpoint"]
    for col in string_cols:
        if col in cleaned.columns:
            cleaned[col] = cleaned[col].fillna("unknown").astype(str).str.strip()
        else:
            cleaned[col] = "unknown"

    # Normalize status
    if "status" in cleaned.columns:
        cleaned["status_raw"] = cleaned["status"]
        cleaned["status"] = cleaned["status"].str.lower()

    # Parse and standardize timestamp
    if "timestamp" in cleaned.columns:
        cleaned["timestamp_dt"] = pd.to_datetime(cleaned["timestamp"], errors="coerce")
        # Fill missing with current timestamp to avoid crashes
        cleaned["timestamp_dt"] = cleaned["timestamp_dt"].fillna(datetime.now())
        cleaned["timestamp"] = cleaned["timestamp_dt"].dt.strftime("%Y-%m-%d %H:%M:%S")

    # Drop pure identical duplicate rows
    cleaned = cleaned.drop_duplicates(subset=["timestamp", "source_ip", "username", "event_type", "endpoint"])

    return cleaned

def get_upload_stats(df: pd.DataFrame) -> dict:
    val_res = validate_csv_upload(df)
    return val_res["stats"]
