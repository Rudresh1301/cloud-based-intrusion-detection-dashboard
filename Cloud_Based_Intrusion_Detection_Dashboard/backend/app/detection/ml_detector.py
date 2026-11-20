import uuid
import logging
from typing import List, Dict, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from app.core.config import ML_CONTAMINATION, ML_MIN_SAMPLES, ML_RANDOM_STATE

log = logging.getLogger(__name__)

class MLAnomalyDetector:
    """
    Unsupervised Behavioral Anomaly Detection Module using Isolation Forest.
    Extracts statistical feature profiles per source IP, scales behavioral dimensions,
    and isolates outlier hosts with detailed human-readable anomaly justifications.
    """

    def __init__(self, contamination: float = ML_CONTAMINATION, min_samples: int = ML_MIN_SAMPLES):
        self.contamination = contamination
        self.min_samples = min_samples
        self.feature_names = [
            "request_count",
            "failed_count",
            "failed_ratio",
            "unique_endpoints",
            "unique_users",
            "suspicious_keyword_count",
            "unique_event_types"
        ]

    def extract_ip_features(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Extracts multidimensional behavioral vectors grouped by source_ip."""
        if df is None or df.empty:
            return pd.DataFrame(columns=self.feature_names), {}

        records = []
        suspicious_keywords = ["select", "union", "script", "admin", "passwd", "eval", "cat", "whoami", "etc"]

        for ip, grp in df.groupby("source_ip"):
            tot_reqs = len(grp)
            status_lower = grp["status"].astype(str).str.lower()
            failed_count = int(status_lower.isin(["failed", "failure", "denied", "401", "403", "blocked"]).sum())
            failed_ratio = failed_count / (tot_reqs if tot_reqs > 0 else 1.0)
            unique_endpoints = int(grp["endpoint"].nunique())
            unique_users = int(grp["username"].dropna().nunique())
            unique_events = int(grp["event_type"].nunique())

            # Keyword matches in payloads
            combined_text = " ".join(grp["endpoint"].astype(str) + " " + grp["event_type"].astype(str)).lower()
            kw_count = sum(combined_text.count(kw) for kw in suspicious_keywords)

            records.append({
                "source_ip": str(ip),
                "request_count": tot_reqs,
                "failed_count": failed_count,
                "failed_ratio": round(failed_ratio, 3),
                "unique_endpoints": unique_endpoints,
                "unique_users": unique_users,
                "suspicious_keyword_count": kw_count,
                "unique_event_types": unique_events,
                "latest_timestamp": str(grp["timestamp"].iloc[-1])
            })

        feature_df = pd.DataFrame(records).set_index("source_ip")
        return feature_df, {}

    def detect_anomalies(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Runs Isolation Forest outlier detection across behavioral IP features.
        Returns explainable ML alert records.
        """
        if df is None or df.empty:
            return []

        features_df, _ = self.extract_ip_features(df)
        if len(features_df) < 3:
            log.info("Dataset contains fewer than 3 distinct IPs. Skipping Isolation Forest to avoid over-fitting.")
            return []

        X = features_df[self.feature_names].values

        try:
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            # Fit Isolation Forest
            eff_contamination = min(0.35, max(0.05, float(self.contamination)))
            iso = IsolationForest(
                contamination=eff_contamination,
                random_state=ML_RANDOM_STATE,
                n_estimators=100
            )
            predictions = iso.fit_predict(X_scaled)  # -1 for outliers, 1 for inliers
            scores = iso.score_samples(X_scaled)    # Lower values represent higher anomaly degree

            ml_alerts = []
            for idx, (ip, row) in enumerate(features_df.iterrows()):
                if predictions[idx] == -1:  # Anomaly flagged
                    raw_score = scores[idx]
                    anomaly_degree = int(np.clip((0.5 - raw_score) * 100, 45, 95))

                    # Build explainable contributing reasons
                    reasons = []
                    if row["failed_ratio"] > 0.4:
                        reasons.append(f"Elevated failure proportion ({int(row['failed_ratio'] * 100)}%)")
                    if row["request_count"] > 25:
                        reasons.append(f"High traffic volume ({row['request_count']} requests)")
                    if row["unique_users"] > 3:
                        reasons.append(f"Credential spray pattern across {row['unique_users']} identities")
                    if row["suspicious_keyword_count"] > 0:
                        reasons.append(f"{row['suspicious_keyword_count']} security signature keyword matches")

                    reason_str = "; ".join(reasons) if reasons else "Statistical behavioral deviation across cluster baseline."

                    severity = "Critical" if anomaly_degree >= 80 else ("High" if anomaly_degree >= 65 else "Medium")

                    ml_alerts.append({
                        "id": f"alert-ml-{uuid.uuid4().hex[:8]}",
                        "timestamp": row["latest_timestamp"],
                        "source_ip": str(ip),
                        "username": "multiple",
                        "alert_type": "Behavioral Anomaly (Isolation Forest)",
                        "severity": severity,
                        "status": "New",
                        "description": f"Machine learning anomaly model identified statistical outlier behavior: {reason_str}",
                        "evidence": f"Isolation Forest Anomaly Score: {raw_score:.3f} (Rank: {anomaly_degree}%) | Requests: {row['request_count']}, Failures: {row['failed_count']}",
                        "recommended_action": "Conduct behavioral traffic inspection; monitor endpoint traversal cadence.",
                        "detection_method": "isolation-forest-ml",
                        "risk_score": anomaly_degree
                    })

            return ml_alerts
        except Exception as e:
            log.warning(f"Isolation Forest anomaly detection error: {e}")
            return []
