"""
Central Intrusion Detection Orchestrator.
Coordinates rule engine evaluation, machine learning anomaly scoring, log enrichment,
IP behavioral intelligence, and overall risk posture calculation.
Enhanced with Streamlit cache_data for instant zero-latency page transitions.
"""
from datetime import datetime
import json
import pandas as pd
import streamlit as st
from core.rule_engine import RuleEngine
from core.ml_detector import MLDetector
from core.log_processor import LogProcessor
from core.ip_analyzer import IPAnalyzer
from core.risk_calculator import RiskCalculator

@st.cache_data(show_spinner=False)
def _run_cached_analysis_pipeline(df: pd.DataFrame, settings_str: str, run_ml: bool = True) -> dict:
    """
    Cached detection pipeline. Avoids repeatedly running rule regexes and ML models on unchanged data.
    """
    if df is None or df.empty:
        empty_alerts = pd.DataFrame(columns=[
            "alert_id", "timestamp", "source_ip", "username",
            "alert_type", "severity", "status", "evidence",
            "recommended_action", "detection_method"
        ])
        calculator = RiskCalculator()
        processor = LogProcessor()
        return {
            "enriched_logs": pd.DataFrame(),
            "rule_alerts": empty_alerts,
            "ml_results": {"success": False, "message": "Empty dataset", "anomalies": pd.DataFrame()},
            "risk_assessment": calculator.calculate_overall_risk(empty_alerts, pd.DataFrame()),
            "dataset_summary": processor.get_dataset_summary(pd.DataFrame()),
            "top_suspicious_ips": [],
            "recommendations": calculator.generate_recommendations(empty_alerts, pd.DataFrame()),
            "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "attack_categories": {},
            "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    try:
        custom_settings = json.loads(settings_str) if settings_str else {}
    except Exception:
        custom_settings = {}

    log_processor = LogProcessor()
    rule_engine = RuleEngine(custom_settings)
    ml_detector = MLDetector()
    ip_analyzer = IPAnalyzer()
    risk_calculator = RiskCalculator()

    # 1. Enrich logs
    enriched = log_processor.enrich_logs(df)

    # 2. Rule-based detection
    rule_alerts = rule_engine.analyze(enriched)

    # 3. ML-based anomaly detection
    ml_results = None
    if run_ml:
        ml_results = ml_detector.train_and_predict(enriched)
    else:
        ml_results = {
            "success": False,
            "message": "ML evaluation disabled in preferences.",
            "anomalies": pd.DataFrame()
        }

    # 4. Dataset summary & risk calculation
    summary = log_processor.get_dataset_summary(enriched)
    risk = risk_calculator.calculate_overall_risk(rule_alerts, enriched)
    top_ips = ip_analyzer.get_top_suspicious_ips(rule_alerts, enriched, top_n=5)
    recs = risk_calculator.generate_recommendations(rule_alerts, enriched)

    # Severity counts
    if not rule_alerts.empty:
        sev_s = rule_alerts["severity"].value_counts()
        severity_counts = {
            "Critical": int(sev_s.get("Critical", 0)),
            "High": int(sev_s.get("High", 0)),
            "Medium": int(sev_s.get("Medium", 0)),
            "Low": int(sev_s.get("Low", 0))
        }
        attack_cats = rule_alerts["alert_type"].value_counts().to_dict()
    else:
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        attack_cats = {}

    return {
        "enriched_logs": enriched,
        "rule_alerts": rule_alerts,
        "ml_results": ml_results,
        "risk_assessment": risk,
        "dataset_summary": summary,
        "top_suspicious_ips": top_ips,
        "recommendations": recs,
        "severity_counts": severity_counts,
        "attack_categories": attack_cats,
        "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


class IntrusionDetector:
    """
    Main detection pipeline wrapper:
    Integrates cached processing with transparent fallbacks.
    """

    def __init__(self, settings: dict | None = None):
        self.settings = settings or {}

    def analyze(self, df: pd.DataFrame, run_ml: bool = True) -> dict:
        """
        Executes complete multi-phase intrusion detection pipeline on input log DataFrame.
        Leverages caching when possible.
        """
        settings_str = json.dumps(self.settings, sort_keys=True) if self.settings else ""
        return _run_cached_analysis_pipeline(df, settings_str, run_ml)


def analyze_logs(logs: pd.DataFrame):
    """
    Backward-compatible entry point for existing starter scripts.
    Returns: (alerts_df, enriched_df)
    """
    detector = IntrusionDetector()
    results = detector.analyze(logs)
    return results["rule_alerts"], results["enriched_logs"]
