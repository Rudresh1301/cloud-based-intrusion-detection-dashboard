import io
import hashlib
import ipaddress
import uuid
import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone
import pandas as pd

from app.core.config import REQUIRED_COLUMNS
from app.detection.rule_engine import RuleEngine
from app.detection.ml_detector import MLAnomalyDetector
from app.detection.ip_analyzer import IPAnalyzer
from app.detection.risk_calculator import RiskCalculator
from app.database.db_service import db_service

log = logging.getLogger(__name__)

class LogProcessor:
    """
    Parses, validates, sanitizes, and evaluates incoming CSV / TXT security logs.
    Executes rule-based and machine-learning threat detection pipelines.
    """

    COLUMN_SYNONYMS = {
        "source_ip": ["source_ip", "ip", "client_ip", "host", "src_ip", "remote_addr", "ip_address"],
        "timestamp": ["timestamp", "time", "date", "datetime", "logged_at", "@timestamp"],
        "username": ["username", "user", "account", "login_user", "uid", "identity"],
        "event_type": ["event_type", "event", "action", "method", "activity", "type"],
        "status": ["status", "response_code", "result", "state", "http_status"],
        "endpoint": ["endpoint", "url", "path", "uri", "request_uri", "resource", "target"]
    }

    def __init__(self):
        self.rule_engine = RuleEngine()
        self.ml_detector = MLAnomalyDetector()
        self.ip_analyzer = IPAnalyzer()
        self.risk_calculator = RiskCalculator()

    def normalize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Maps synonym column headers to standard canonical schema."""
        rename_map = {}
        for canonical, aliases in self.COLUMN_SYNONYMS.items():
            for col in df.columns:
                clean_col = str(col).strip().lower().replace(" ", "_")
                if clean_col in aliases and canonical not in df.columns:
                    rename_map[col] = canonical
                    break
        if rename_map:
            df = df.rename(columns=rename_map)
        return df

    def parse_file(self, content_bytes: bytes, filename: str) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Parses raw uploaded bytes (CSV or structured TXT) into a DataFrame with validation stats."""
        try:
            if filename.endswith(".csv"):
                df = pd.read_csv(io.BytesIO(content_bytes), encoding="utf-8", on_bad_lines="skip")
            else:
                # Text log format: try comma, tab, or space delimiters
                try:
                    df = pd.read_csv(io.BytesIO(content_bytes), sep=r"\s+", encoding="utf-8", on_bad_lines="skip")
                except Exception:
                    df = pd.read_csv(io.BytesIO(content_bytes), sep=",", encoding="utf-8", on_bad_lines="skip")
        except Exception as e:
            raise ValueError(f"Could not parse file structure: {str(e)}")

        df = self.normalize_columns(df)
        return df, self.validate_dataframe(df)

    def validate_dataframe(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Performs strict validation checks against the parsed DataFrame."""
        errors = []
        warnings = []

        if df is None or df.empty:
            return {
                "valid": False,
                "errors": ["Uploaded file contains zero records or is empty."],
                "warnings": [],
                "stats": {"total_rows": 0, "valid_rows": 0, "invalid_rows": 0, "duplicate_rows": 0},
                "preview": []
            }

        missing_cols = [c for c in REQUIRED_COLUMNS if c not in df.columns]
        if missing_cols:
            errors.append(f"Missing mandatory column(s): {', '.join(sorted(missing_cols))}. Expected: {', '.join(REQUIRED_COLUMNS)}")

        total_rows = len(df)
        duplicates = int(df.duplicated().sum())
        if duplicates > 0:
            warnings.append(f"Identified {duplicates} duplicate row(s) in upload.")

        invalid_ips = 0
        if "source_ip" in df.columns:
            for ip in df["source_ip"].dropna():
                try:
                    ipaddress.ip_address(str(ip).strip())
                except ValueError:
                    invalid_ips += 1
            if invalid_ips > 0:
                warnings.append(f"Detected {invalid_ips} syntactically invalid IP address value(s).")

        missing_fields = int(df.isna().sum().sum())
        if missing_fields > 0:
            warnings.append(f"Found {missing_fields} empty or null field values in upload.")

        is_valid = len(errors) == 0

        # Create clean preview sample
        preview = df.head(8).fillna("").to_dict(orient="records")

        return {
            "valid": is_valid,
            "errors": errors,
            "warnings": warnings,
            "stats": {
                "total_rows": total_rows,
                "valid_rows": total_rows - invalid_ips,
                "invalid_rows": invalid_ips,
                "duplicate_rows": duplicates,
                "detected_columns": list(df.columns)
            },
            "preview": preview
        }

    def process_and_analyze(self, content_bytes: bytes, filename: str) -> Dict[str, Any]:
        """
        Executes complete log processing pipeline:
        1. Validate & normalize
        2. Upload to Cloud Storage or local fallback
        3. Run Rule Heuristics
        4. Run Isolation Forest ML
        5. Correlate IP Intelligence
        6. Calculate Risk
        7. Persist to Firestore / SQLite
        """
        file_hash = hashlib.sha256(content_bytes).hexdigest()
        df, validation = self.parse_file(content_bytes, filename)

        if not validation["valid"]:
            return {
                "success": False,
                "message": "Validation failed on uploaded file.",
                "validation": validation
            }

        # Save raw file to storage
        storage_meta = db_service.storage_service.save_uploaded_file(filename, content_bytes)

        # Run Rule-based detection
        rule_alerts = self.rule_engine.analyze(df)

        # Run ML Anomaly Detection
        ml_alerts = self.ml_detector.detect_anomalies(df)

        # Combine alerts without duplicate IDs
        all_alerts = rule_alerts + ml_alerts

        # Tag classification on raw logs
        alerted_ips = {a["source_ip"]: a["alert_type"] for a in all_alerts}
        raw_logs_to_store = []
        for idx, row in df.iterrows():
            log_id = f"log-{file_hash[:8]}-{idx}"
            ip = str(row["source_ip"]).strip()
            classification = alerted_ips.get(ip, "Normal")
            raw_logs_to_store.append({
                "id": log_id,
                "timestamp": str(row["timestamp"]),
                "source_ip": ip,
                "username": str(row.get("username", "")),
                "event_type": str(row["event_type"]),
                "status": str(row["status"]),
                "endpoint": str(row["endpoint"]),
                "classification": classification,
                "risk_score": 85 if classification != "Normal" else 0
            })

        # Save logs to database
        db_service.save_logs(raw_logs_to_store)

        # Save alerts to database
        db_service.save_alerts(all_alerts)

        # Analyze and save IP Intelligence
        ip_profiles = self.ip_analyzer.analyze_ips(df, all_alerts)
        db_service.save_ip_intel(ip_profiles)

        # Calculate overall risk
        overall_risk = self.risk_calculator.calculate_overall_risk(all_alerts, len(df))

        # Record analysis history
        history_id = f"hist-{uuid.uuid4().hex[:8]}"
        analysis_history_record = {
            "id": history_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "filename": filename,
            "total_records": len(df),
            "threats_found": len(all_alerts),
            "suspicious_ips": len([ip for ip in ip_profiles if ip["risk_score"] > 0]),
            "risk_level": overall_risk["level"],
            "storage_url": storage_meta.get("download_url", ""),
            "summary": {
                "file_hash": file_hash,
                "storage_type": storage_meta["storage_type"],
                "rule_alerts_count": len(rule_alerts),
                "ml_alerts_count": len(ml_alerts),
                "risk_score": overall_risk["percentage"]
            }
        }
        db_service.save_analysis_history(analysis_history_record)

        return {
            "success": True,
            "filename": filename,
            "total_records": len(df),
            "threats_found": len(all_alerts),
            "suspicious_ips_count": len([ip for ip in ip_profiles if ip["risk_score"] > 0]),
            "overall_risk": overall_risk,
            "storage": storage_meta,
            "rule_alerts_count": len(rule_alerts),
            "ml_alerts_count": len(ml_alerts),
            "alerts": all_alerts[:15],
            "ip_intelligence": ip_profiles[:10]
        }

log_processor = LogProcessor()
