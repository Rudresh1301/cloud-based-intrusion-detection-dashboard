"""
Firebase Firestore database integration.
Optimized with query limits, socket timeout guards, and silent local fallback.
"""
import logging
from datetime import datetime, timezone
import uuid
import pandas as pd
import streamlit as st

log = logging.getLogger(__name__)

class FirebaseDatabase:
    """Cloud Firestore storage for alerts, analysis history, settings, and logs."""

    def __init__(self, firestore_client=None):
        self.db = firestore_client

    def is_connected(self) -> bool:
        return self.db is not None

    def save_alerts(self, alerts_df: pd.DataFrame):
        if not self.is_connected() or alerts_df is None or alerts_df.empty:
            return
        try:
            batch = self.db.batch()
            alerts_ref = self.db.collection("alerts")
            now = datetime.now(timezone.utc).isoformat()
            
            # Firestore batch limit is 500 operations per batch
            for idx, row in enumerate(alerts_df.to_dict('records')):
                if idx >= 450:
                    break
                aid = str(row.get("alert_id", uuid.uuid4()))
                doc_ref = alerts_ref.document(aid)
                data = {
                    "id": aid,
                    "timestamp": str(row.get("timestamp", "")),
                    "source_ip": str(row.get("source_ip", "")),
                    "alert_type": str(row.get("alert_type", "")),
                    "severity": str(row.get("severity", "")),
                    "status": str(row.get("status", "New")),
                    "description": str(row.get("description", row.get("evidence", ""))),
                    "evidence": str(row.get("evidence", "")),
                    "username": str(row.get("username", "")),
                    "recommended_action": str(row.get("recommended_action", "")),
                    "detection_method": str(row.get("detection_method", "rule-based")),
                    "updated_at": now
                }
                batch.set(doc_ref, data)
            batch.commit(timeout=5.0)
            log.info("Saved alerts to Firestore batch.")
        except Exception as e:
            log.error(f"Error saving alerts to Firestore: {e}")

    def get_alerts(self, filters: dict | None = None, limit: int = 100):
        if not self.is_connected():
            return []
        try:
            query = self.db.collection("alerts").order_by("timestamp", direction="DESCENDING").limit(limit)
            docs = query.stream(timeout=5.0)
            results = [doc.to_dict() for doc in docs]
            
            if filters:
                if "severity" in filters and filters["severity"]:
                    results = [r for r in results if r.get("severity") in filters["severity"]]
                if "status" in filters and filters["status"]:
                    results = [r for r in results if r.get("status") in filters["status"]]
                if "source_ip" in filters and filters["source_ip"]:
                    results = [r for r in results if filters["source_ip"] in r.get("source_ip", "")]
            
            return results
        except Exception as e:
            log.error(f"Error getting alerts from Firestore: {e}")
            return []

    def update_alert_status(self, alert_id: str, new_status: str):
        if not self.is_connected():
            return
        try:
            doc_ref = self.db.collection("alerts").document(alert_id)
            doc = doc_ref.get(timeout=3.0)
            old_status = "Unknown"
            if doc.exists:
                old_status = doc.to_dict().get("status", "Unknown")
            
            now = datetime.now(timezone.utc).isoformat()
            doc_ref.update({"status": new_status, "updated_at": now}, timeout=3.0)
            
            self.db.collection("alert_status_log").add({
                "alert_id": alert_id,
                "old_status": old_status,
                "new_status": new_status,
                "changed_at": now
            }, timeout=3.0)
            log.info(f"Updated alert {alert_id} status to {new_status}")
        except Exception as e:
            log.error(f"Error updating alert status in Firestore: {e}")

    def get_alert_counts(self) -> dict:
        alerts = self.get_alerts(limit=500)
        counts = {}
        for a in alerts:
            s = a.get("status", "New")
            counts[s] = counts.get(s, 0) + 1
        return counts

    def save_analysis(self, summary: dict):
        if not self.is_connected():
            return
        try:
            now = datetime.now(timezone.utc).isoformat()
            data = {
                "id": str(uuid.uuid4()),
                "timestamp": now,
                "total_records": summary.get("total_records", 0),
                "threats_found": summary.get("threats_found", 0),
                "dataset_name": summary.get("dataset_name", "uploaded"),
                "summary": summary,
                "created_at": now
            }
            self.db.collection("analysis_history").add(data, timeout=4.0)
        except Exception as e:
            log.error(f"Error saving analysis to Firestore: {e}")

    def get_analysis_history(self):
        if not self.is_connected():
            return []
        try:
            docs = self.db.collection("analysis_history").order_by("created_at", direction="DESCENDING").limit(20).stream(timeout=4.0)
            return [d.to_dict() for d in docs]
        except Exception as e:
            log.error(f"Error getting analysis history from Firestore: {e}")
            return []

    def save_setting(self, key: str, value):
        if not self.is_connected():
            return
        try:
            now = datetime.now(timezone.utc).isoformat()
            self.db.collection("settings").document(key).set({
                "key": key,
                "value": value,
                "updated_at": now
            }, timeout=3.0)
        except Exception as e:
            log.error(f"Error saving setting to Firestore: {e}")

    def get_setting(self, key: str, default=None):
        if not self.is_connected():
            return default
        try:
            doc = self.db.collection("settings").document(key).get(timeout=3.0)
            if doc.exists:
                return doc.to_dict().get("value", default)
            return default
        except Exception as e:
            log.error(f"Error getting setting from Firestore: {e}")
            return default
