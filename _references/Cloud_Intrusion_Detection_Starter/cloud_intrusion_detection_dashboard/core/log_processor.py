"""
Log Ingestion and Enrichment Processor.
Transforms raw CSV and TXT access records into standardized, feature-enriched DataFrames.
"""
import io
import re
import pandas as pd
from datetime import datetime
from utils.validators import validate_csv_upload, clean_dataframe

class LogProcessor:
    """Processes, standardizes and enriches log files."""

    def __init__(self):
        self.common_apache_regex = re.compile(
            r'^(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<event_type>\S+) (?P<endpoint>\S+) [^"]*" (?P<status>\d{3}) (?P<bytes>\S+)'
        )

    def process_csv(self, file_source) -> dict:
        """
        Parses CSV from file buffer, path, or string.
        Returns:
            dict with {success: bool, data: DataFrame, stats: dict, errors: list, warnings: list}
        """
        try:
            if isinstance(file_source, (str, bytes)):
                if isinstance(file_source, bytes):
                    df_raw = pd.read_csv(io.BytesIO(file_source))
                elif "\n" in file_source:
                    df_raw = pd.read_csv(io.StringIO(file_source))
                else:
                    df_raw = pd.read_csv(file_source)
            else:
                # Streamlit UploadedFile or file-like object
                df_raw = pd.read_csv(file_source)

            val_res = validate_csv_upload(df_raw)
            if not val_res["valid"]:
                return {
                    "success": False,
                    "data": None,
                    "stats": val_res["stats"],
                    "errors": val_res["errors"],
                    "warnings": val_res["warnings"]
                }

            cleaned = clean_dataframe(df_raw)
            enriched = self.enrich_logs(cleaned)

            return {
                "success": True,
                "data": enriched,
                "stats": val_res["stats"],
                "errors": [],
                "warnings": val_res["warnings"]
            }

        except Exception as e:
            return {
                "success": False,
                "data": None,
                "stats": {},
                "errors": [f"CSV parsing failed: {str(e)}"],
                "warnings": []
            }

    def process_txt(self, content_str: str) -> dict:
        """
        Attempts to parse plain text / Apache Combined / Nginx logs into our schema.
        """
        lines = content_str.strip().split("\n")
        rows = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            m = self.common_apache_regex.match(line)
            if m:
                d = m.groupdict()
                rows.append({
                    "timestamp": d["timestamp"],
                    "source_ip": d["source_ip"],
                    "username": "guest",
                    "event_type": d["event_type"],
                    "status": "success" if d["status"].startswith("2") else ("failed" if d["status"].startswith("4") else "server_error"),
                    "endpoint": d["endpoint"]
                })
            else:
                # Comma/tab fallback
                parts = re.split(r'[,\t|]', line)
                if len(parts) >= 6:
                    rows.append({
                        "timestamp": parts[0].strip(),
                        "source_ip": parts[1].strip(),
                        "username": parts[2].strip(),
                        "event_type": parts[3].strip(),
                        "status": parts[4].strip(),
                        "endpoint": parts[5].strip(),
                    })

        if not rows:
            return {
                "success": False,
                "data": None,
                "stats": {},
                "errors": ["Could not parse log lines. Supported formats: CSV with header or standard Apache/Nginx access log."],
                "warnings": []
            }

        df_raw = pd.DataFrame(rows)
        return self.process_csv(df_raw.to_csv(index=False))

    def enrich_logs(self, df: pd.DataFrame) -> pd.DataFrame:
        """Adds temporal, status and categorization helper columns."""
        enriched = df.copy()
        
        # Ensure timestamp is datetime
        ts_dt = pd.to_datetime(enriched["timestamp"], errors="coerce").fillna(datetime.now())
        enriched["timestamp_dt"] = ts_dt
        enriched["hour"] = ts_dt.dt.hour
        enriched["day_name"] = ts_dt.dt.day_name()
        enriched["date"] = ts_dt.dt.date

        # Failure & Blocked detection
        status_s = enriched["status"].astype(str).str.lower()
        enriched["is_failed"] = status_s.isin(["failed", "failure", "denied", "401", "403"])
        enriched["is_blocked"] = status_s.isin(["blocked", "dropped", "rejected"])
        enriched["is_success"] = status_s.isin(["success", "successful", "ok", "200", "201"])

        # Fast vectorized endpoint categorization
        ep_lower = enriched["endpoint"].astype(str).str.lower()
        import numpy as np
        conditions = [
            ep_lower.str.contains("login|auth|signin|logout|token", na=False),
            ep_lower.str.contains("/api|/v1|/v2|/graphql", na=False),
            ep_lower.str.contains("admin|config|debug|manage", na=False),
            ep_lower.str.contains(r"\.pdf|\.csv|\.json|\.zip|download", na=False),
        ]
        choices = ["Authentication", "API Endpoint", "Administrative", "File Transfer"]
        enriched["endpoint_category"] = np.select(conditions, choices, default="Web Surface")

        # IP request count per dataset
        ip_counts = enriched["source_ip"].value_counts()
        enriched["ip_total_events"] = enriched["source_ip"].map(ip_counts)

        return enriched

    def get_dataset_summary(self, df: pd.DataFrame) -> dict:
        """Calculates comprehensive summary metrics for dashboard cards and reports."""
        if df is None or df.empty:
            return {
                "total_records": 0,
                "unique_ips": 0,
                "unique_users": 0,
                "unique_endpoints": 0,
                "blocked_attempts": 0,
                "failed_attempts": 0,
                "success_attempts": 0,
                "time_min": "N/A",
                "time_max": "N/A",
                "top_endpoints": {},
                "top_event_types": {}
            }

        status_s = df["status"].astype(str).str.lower()
        blocked_count = int(status_s.isin(["blocked", "dropped", "rejected"]).sum())
        failed_count = int(status_s.isin(["failed", "failure", "denied", "401", "403"]).sum())
        success_count = int(status_s.isin(["success", "ok", "200"]).sum())

        ts_series = pd.to_datetime(df["timestamp"], errors="coerce").dropna()
        time_min = ts_series.min().strftime("%Y-%m-%d %H:%M") if not ts_series.empty else "N/A"
        time_max = ts_series.max().strftime("%Y-%m-%d %H:%M") if not ts_series.empty else "N/A"

        return {
            "total_records": len(df),
            "unique_ips": int(df["source_ip"].nunique()),
            "unique_users": int(df["username"].nunique()),
            "unique_endpoints": int(df["endpoint"].nunique()),
            "blocked_attempts": blocked_count,
            "failed_attempts": failed_count,
            "success_attempts": success_count,
            "time_min": time_min,
            "time_max": time_max,
            "top_endpoints": df["endpoint"].value_counts().head(5).to_dict(),
            "top_event_types": df["event_type"].value_counts().head(5).to_dict()
        }
