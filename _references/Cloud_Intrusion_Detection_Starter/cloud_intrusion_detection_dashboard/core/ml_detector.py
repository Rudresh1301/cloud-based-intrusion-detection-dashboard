"""
Machine Learning Anomaly Detection Module using Isolation Forest.
Extracts per-IP behavioral features, performs unsupervised outlier detection,
and produces explainable reasoning for each flagged anomaly.
"""
import logging
import numpy as np
import pandas as pd
from config.settings import ML_CONTAMINATION, ML_MIN_SAMPLES, ML_RANDOM_STATE

log = logging.getLogger(__name__)

class MLDetector:
    """
    Unsupervised behavioral anomaly detector based on Scikit-Learn IsolationForest.
    Computes statistical feature embeddings per IP:
    - request volume
    - failure ratio
    - distinct endpoints
    - distinct user identities
    - suspicious keyword presence
    """

    def __init__(self, contamination: float = ML_CONTAMINATION, random_state: int = ML_RANDOM_STATE):
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.scaler = None
        self.feature_names = [
            "request_count",
            "failed_count",
            "failed_ratio",
            "unique_endpoints",
            "unique_users",
            "suspicious_keyword_count",
            "unique_event_types"
        ]
        self.is_trained = False
        self.feature_stats = {}

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Aggregates raw log lines into IP-level behavioral vectors.
        Returns: DataFrame indexed by source_ip.
        """
        if df is None or df.empty:
            return pd.DataFrame(columns=self.feature_names)

        records = []
        suspicious_words = ["injection", "xss", "script", "admin", "traversal", "passwd", "drop", "select"]

        for ip, grp in df.groupby("source_ip"):
            tot_reqs = len(grp)
            
            # Failed requests
            status_s = grp["status"].astype(str).str.lower()
            failed_reqs = int(status_s.isin(["failed", "failure", "denied", "401", "403", "blocked"]).sum())
            failed_ratio = failed_reqs / (tot_reqs if tot_reqs > 0 else 1)
            
            # Endpoints and users
            uniq_eps = int(grp["endpoint"].nunique())
            uniq_users = int(grp["username"].nunique())
            uniq_events = int(grp["event_type"].nunique())

            # Keyword checks
            full_text = (grp["event_type"].astype(str) + " " + grp["endpoint"].astype(str)).str.lower()
            susp_count = sum(full_text.str.contains(w, na=False).sum() for w in suspicious_words)

            records.append({
                "source_ip": str(ip),
                "request_count": tot_reqs,
                "failed_count": failed_reqs,
                "failed_ratio": round(failed_ratio, 3),
                "unique_endpoints": uniq_eps,
                "unique_users": uniq_users,
                "suspicious_keyword_count": int(susp_count),
                "unique_event_types": uniq_events
            })

        feat_df = pd.DataFrame(records).set_index("source_ip")
        return feat_df

    def train_and_predict(self, df: pd.DataFrame) -> dict:
        """
        Extracts features, trains Isolation Forest (if sufficient data), and scores anomalies.
        Returns dict with:
        - success: bool
        - message: str
        - features: DataFrame
        - anomalies: DataFrame of anomalous IPs with explanations
        - contamination: float
        """
        features_df = self.extract_features(df)
        
        if len(features_df) < 3:
            return {
                "success": False,
                "message": f"Dataset has only {len(features_df)} unique IP(s). Isolation Forest requires at least 3 distinct IPs for comparative anomaly scoring.",
                "features": features_df,
                "anomalies": pd.DataFrame(),
                "model_info": self.get_model_info()
            }

        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            log.warning("scikit-learn not available. Falling back to statistical Z-score anomaly scoring.")
            return self._statistical_fallback(features_df)

        try:
            # Scaler
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(features_df[self.feature_names])

            # Contamination dynamic adjustment for smaller datasets
            n_samples = len(features_df)
            eff_contamination = min(self.contamination, max(0.05, 1.0 / n_samples))

            self.model = IsolationForest(
                n_estimators=100,
                contamination=eff_contamination,
                random_state=self.random_state
            )
            preds = self.model.fit_predict(X_scaled)
            scores = self.model.decision_function(X_scaled)

            features_df["anomaly_score"] = np.round(scores, 3)
            # -1 is anomalous in Isolation Forest, 1 is inlier
            features_df["is_anomaly"] = preds == -1
            self.is_trained = True

            # Calculate means and stds for human explanations
            means = features_df[self.feature_names].mean()
            stds = features_df[self.feature_names].std().replace(0, 1)

            # Build explainable anomalies table
            anomalous_rows = features_df[features_df["is_anomaly"]].copy()
            explanations = []

            for ip, row in anomalous_rows.iterrows():
                reasons = []
                if row["request_count"] > (means["request_count"] + 1.5 * stds["request_count"]):
                    reasons.append(f"Request volume ({int(row['request_count'])}) well above average ({means['request_count']:.1f})")
                if row["failed_ratio"] > 0.4:
                    reasons.append(f"High failure rate ({row['failed_ratio']*100:.0f}%)")
                if row["suspicious_keyword_count"] > 0:
                    reasons.append(f"Detected {int(row['suspicious_keyword_count'])} suspicious query/payload keywords")
                if row["unique_endpoints"] > (means["unique_endpoints"] + 1.5 * stds["unique_endpoints"]):
                    reasons.append(f"Scanning behavior: accessed {int(row['unique_endpoints'])} distinct endpoints")
                
                if not reasons:
                    reasons.append("Unusual multi-dimensional feature divergence identified by Isolation Forest.")

                explanations.append("; ".join(reasons))

            anomalous_rows["anomaly_reasons"] = explanations
            anomalous_rows = anomalous_rows.reset_index()

            return {
                "success": True,
                "message": f"Isolation Forest successfully trained on {len(features_df)} IP behavioral profiles. Identified {len(anomalous_rows)} anomaly candidate(s).",
                "features": features_df.reset_index(),
                "anomalies": anomalous_rows,
                "model_info": self.get_model_info()
            }

        except Exception as e:
            log.error(f"Error in ML anomaly detection: {e}")
            return self._statistical_fallback(features_df)

    def _statistical_fallback(self, features_df: pd.DataFrame) -> dict:
        """Statistical heuristic fallback if scikit-learn fails or is missing."""
        means = features_df[self.feature_names].mean()
        stds = features_df[self.feature_names].std().replace(0, 1)

        # Flag any IP that is 2 std deviations above mean on requests or failures
        is_anom = (
            (features_df["request_count"] > means["request_count"] + 2 * stds["request_count"]) |
            (features_df["failed_ratio"] > 0.6) |
            (features_df["suspicious_keyword_count"] >= 2)
        )
        features_df["is_anomaly"] = is_anom
        features_df["anomaly_score"] = -0.5 * is_anom.astype(float)
        
        anom_rows = features_df[features_df["is_anomaly"]].copy()
        anom_rows["anomaly_reasons"] = "Statistical threshold outlier in request volume or failure ratio."
        anom_rows = anom_rows.reset_index()

        return {
            "success": True,
            "message": f"Statistical outlier detection completed on {len(features_df)} IPs. Flagged {len(anom_rows)} outlier(s).",
            "features": features_df.reset_index(),
            "anomalies": anom_rows,
            "model_info": {"algorithm": "Statistical Z-Score (Fallback)", "status": "Active"}
        }

    def get_model_info(self) -> dict:
        return {
            "algorithm": "Isolation Forest (Ensemble Tree Anomaly Detection)",
            "n_estimators": 100,
            "contamination": self.contamination,
            "features": self.feature_names,
            "supervised": False,
            "note": "Evaluates unsupervised density isolation. Negative anomaly scores reflect higher outlier likelihood."
        }
