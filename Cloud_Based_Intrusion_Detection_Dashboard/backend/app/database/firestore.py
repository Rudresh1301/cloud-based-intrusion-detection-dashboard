import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from app.core.config import FIREBASE_CREDENTIALS_PATH, FIREBASE_PROJECT_ID

log = logging.getLogger(__name__)

class FirestoreDatabase:
    """Production Cloud Database implementation using Google Cloud Firestore."""

    def __init__(self):
        self.db = None
        self.is_initialized = False
        self._init_firestore()

    def _init_firestore(self):
        try:
            import firebase_admin
            from firebase_admin import credentials, firestore

            # Check if credentials file is provided and exists
            if FIREBASE_CREDENTIALS_PATH and os.path.exists(FIREBASE_CREDENTIALS_PATH):
                if not firebase_admin._apps:
                    cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
                    firebase_admin.initialize_app(cred, {
                        'projectId': FIREBASE_PROJECT_ID or None
                    })
                self.db = firestore.client()
                self.is_initialized = True
                log.info("Firestore client initialized successfully with service account.")
            elif os.getenv("GOOGLE_APPLICATION_CREDENTIALS") and os.path.exists(os.getenv("GOOGLE_APPLICATION_CREDENTIALS")):
                if not firebase_admin._apps:
                    firebase_admin.initialize_app()
                self.db = firestore.client()
                self.is_initialized = True
                log.info("Firestore client initialized using GOOGLE_APPLICATION_CREDENTIALS.")
            else:
                log.info("Firebase credentials not detected. Firestore is in unconfigured state.")
        except Exception as e:
            log.warning(f"Failed to initialize Firestore: {e}")
            self.db = None
            self.is_initialized = False

    def is_connected(self) -> bool:
        if not self.is_initialized or self.db is None:
            return False
        try:
            # Perform lightweight read to verify active connectivity
            collections = self.db.collections()
            return True
        except Exception as e:
            log.warning(f"Firestore connectivity probe failed: {e}")
            return False

    def ping(self) -> Dict[str, Any]:
        """Real cloud connectivity health check."""
        if not self.is_initialized or self.db is None:
            return {
                "status": "unconfigured",
                "connected": False,
                "latency_ms": None,
                "details": "Firebase service account credentials not configured or file not found."
            }
        import time
        start = time.time()
        try:
            # Attempt to query a single collection metadata
            list(self.db.collection("system_health").limit(1).stream())
            latency = round((time.time() - start) * 1000, 2)
            return {
                "status": "connected",
                "connected": True,
                "latency_ms": latency,
                "details": f"Connected to Firestore project '{FIREBASE_PROJECT_ID or 'default'}'."
            }
        except Exception as e:
            return {
                "status": "error",
                "connected": False,
                "latency_ms": None,
                "details": f"Firestore connection error: {str(e)}"
            }

    # --- Logs ---
    def save_logs(self, logs: List[Dict[str, Any]]) -> int:
        if not self.is_connected() or not logs:
            return 0
        try:
            batch = self.db.batch()
            col_ref = self.db.collection("security_logs")
            count = 0
            for item in logs[:450]:  # Firestore limit is 500 per batch
                doc_ref = col_ref.document(str(item["id"]))
                batch.set(doc_ref, item, merge=True)
                count += 1
            batch.commit()
            return count
        except Exception as e:
            log.error(f"Firestore save_logs error: {e}")
            raise

    def get_logs(self, page: int = 1, page_size: int = 50, search: str = "", classification: str = "") -> Dict[str, Any]:
        if not self.is_connected():
            return {"items": [], "total": 0, "page": page, "page_size": page_size}
        try:
            col_ref = self.db.collection("security_logs").order_by("timestamp", direction="DESCENDING")
            if classification and classification.lower() != "all":
                col_ref = col_ref.where("classification", "==", classification)
            
            # Streaming results with pagination
            docs = list(col_ref.limit(page * page_size).stream())
            start_idx = (page - 1) * page_size
            page_docs = docs[start_idx:start_idx + page_size]
            items = [d.to_dict() for d in page_docs]
            return {"items": items, "total": len(docs), "page": page, "page_size": page_size}
        except Exception as e:
            log.error(f"Firestore get_logs error: {e}")
            return {"items": [], "total": 0, "page": page, "page_size": page_size}

    # --- Alerts ---
    def save_alerts(self, alerts: List[Dict[str, Any]]) -> int:
        if not self.is_connected() or not alerts:
            return 0
        try:
            batch = self.db.batch()
            col_ref = self.db.collection("threat_alerts")
            count = 0
            for alert in alerts[:450]:
                doc_ref = col_ref.document(str(alert["id"]))
                batch.set(doc_ref, alert, merge=True)
                count += 1
            batch.commit()
            return count
        except Exception as e:
            log.error(f"Firestore save_alerts error: {e}")
            raise

    def get_alerts(self, page: int = 1, page_size: int = 50, severity: str = "", status: str = "", search: str = "") -> Dict[str, Any]:
        if not self.is_connected():
            return {"items": [], "total": 0, "page": page, "page_size": page_size}
        try:
            col_ref = self.db.collection("threat_alerts").order_by("timestamp", direction="DESCENDING")
            if severity and severity.lower() != "all":
                col_ref = col_ref.where("severity", "==", severity)
            if status and status.lower() != "all":
                col_ref = col_ref.where("status", "==", status)
            
            docs = list(col_ref.limit(page * page_size).stream())
            start_idx = (page - 1) * page_size
            page_docs = docs[start_idx:start_idx + page_size]
            items = [d.to_dict() for d in page_docs]
            return {"items": items, "total": len(docs), "page": page, "page_size": page_size}
        except Exception as e:
            log.error(f"Firestore get_alerts error: {e}")
            return {"items": [], "total": 0, "page": page, "page_size": page_size}

    def update_alert_status(self, alert_id: str, new_status: str) -> bool:
        if not self.is_connected():
            return False
        try:
            doc_ref = self.db.collection("threat_alerts").document(alert_id)
            doc_ref.update({
                "status": new_status,
                "updated_at": datetime.now(timezone.utc).isoformat()
            })
            return True
        except Exception as e:
            log.error(f"Firestore update_alert_status error: {e}")
            return False

    # --- IP Intelligence ---
    def save_ip_intel(self, ip_data_list: List[Dict[str, Any]]):
        if not self.is_connected() or not ip_data_list:
            return
        try:
            batch = self.db.batch()
            col_ref = self.db.collection("ip_intelligence")
            for item in ip_data_list[:450]:
                doc_ref = col_ref.document(str(item["ip_address"]).replace(".", "_"))
                batch.set(doc_ref, item, merge=True)
            batch.commit()
        except Exception as e:
            log.error(f"Firestore save_ip_intel error: {e}")

    def get_ip_intel_list(self, search: str = "", threat_status: str = "") -> List[Dict[str, Any]]:
        if not self.is_connected():
            return []
        try:
            col_ref = self.db.collection("ip_intelligence").order_by("risk_score", direction="DESCENDING")
            if threat_status and threat_status.lower() != "all":
                col_ref = col_ref.where("threat_status", "==", threat_status)
            docs = col_ref.limit(100).stream()
            items = [d.to_dict() for d in docs]
            if search:
                items = [item for item in items if search in item.get("ip_address", "")]
            return items
        except Exception as e:
            log.error(f"Firestore get_ip_intel_list error: {e}")
            return []

    # --- Analysis History ---
    def save_analysis_history(self, history: Dict[str, Any]):
        if not self.is_connected():
            return
        try:
            doc_ref = self.db.collection("analysis_history").document(str(history["id"]))
            doc_ref.set(history)
        except Exception as e:
            log.error(f"Firestore save_analysis_history error: {e}")

    def get_analysis_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        if not self.is_connected():
            return []
        try:
            docs = self.db.collection("analysis_history").order_by("timestamp", direction="DESCENDING").limit(limit).stream()
            return [d.to_dict() for d in docs]
        except Exception as e:
            log.error(f"Firestore get_analysis_history error: {e}")
            return []

    # --- Reports ---
    def save_report(self, report: Dict[str, Any]):
        if not self.is_connected():
            return
        try:
            doc_ref = self.db.collection("reports").document(str(report["id"]))
            doc_ref.set(report)
        except Exception as e:
            log.error(f"Firestore save_report error: {e}")

    def get_reports(self) -> List[Dict[str, Any]]:
        if not self.is_connected():
            return []
        try:
            docs = self.db.collection("reports").order_by("generated_at", direction="DESCENDING").stream()
            return [d.to_dict() for d in docs]
        except Exception as e:
            log.error(f"Firestore get_reports error: {e}")
            return []
