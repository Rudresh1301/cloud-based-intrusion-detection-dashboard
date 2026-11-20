import os
import shutil
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from app.core.config import FIREBASE_STORAGE_BUCKET, DATA_DIR

log = logging.getLogger(__name__)

class StorageService:
    """
    Dual Cloud / Local Storage Service.
    Uploads logs and reports to Firebase Cloud Storage when configured;
    falls back to local filesystem storage with distinct metadata and audit indicators.
    """

    def __init__(self):
        self.bucket = None
        self.is_cloud_active = False
        self.local_storage_dir = DATA_DIR / "storage"
        self.local_storage_dir.mkdir(parents=True, exist_ok=True)
        self._init_cloud_storage()

    def _init_cloud_storage(self):
        try:
            import firebase_admin
            from firebase_admin import storage

            if firebase_admin._apps and FIREBASE_STORAGE_BUCKET:
                self.bucket = storage.bucket(FIREBASE_STORAGE_BUCKET)
                self.is_cloud_active = True
                log.info(f"Firebase Storage bucket '{FIREBASE_STORAGE_BUCKET}' connected.")
            else:
                self.bucket = None
                self.is_cloud_active = False
                log.info("Firebase Storage unconfigured. Using local storage fallback.")
        except Exception as e:
            log.warning(f"Could not initialize Firebase Storage: {e}")
            self.bucket = None
            self.is_cloud_active = False

    def ping(self) -> Dict[str, Any]:
        """Verify storage health."""
        if not self.is_cloud_active or self.bucket is None:
            return {
                "status": "fallback",
                "connected": False,
                "provider": "Local Object Storage (data/storage)",
                "details": "Firebase Storage bucket not configured. Local filesystem active for development."
            }
        try:
            # Check bucket exists
            exists = self.bucket.exists()
            return {
                "status": "connected" if exists else "error",
                "connected": exists,
                "provider": "Firebase Cloud Storage (Google Cloud)",
                "details": f"Bucket '{FIREBASE_STORAGE_BUCKET}' verified active."
            }
        except Exception as e:
            return {
                "status": "error",
                "connected": False,
                "provider": "Firebase Cloud Storage",
                "details": f"Storage probe error: {str(e)}"
            }

    def save_uploaded_file(self, filename: str, content_bytes: bytes, content_type: str = "text/csv") -> Dict[str, Any]:
        """
        Saves uploaded file to Cloud Storage (if available) or local fallback.
        Returns metadata including storage_type, file_path, and access url.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{filename}"

        if self.is_cloud_active and self.bucket is not None:
            try:
                blob = self.bucket.blob(f"uploads/{safe_filename}")
                blob.upload_from_string(content_bytes, content_type=content_type)
                blob.make_public()
                return {
                    "storage_type": "Firebase Cloud Storage",
                    "file_path": f"uploads/{safe_filename}",
                    "download_url": blob.public_url,
                    "is_cloud": True,
                    "size_bytes": len(content_bytes)
                }
            except Exception as e:
                log.error(f"Failed to upload to Firebase Cloud Storage: {e}")
                # We do NOT silently claim cloud success
                raise RuntimeError(f"Cloud Storage upload failed: {str(e)}")

        # Local Fallback
        dest_path = self.local_storage_dir / "uploads"
        dest_path.mkdir(parents=True, exist_ok=True)
        file_path = dest_path / safe_filename
        with open(file_path, "wb") as f:
            f.write(content_bytes)

        return {
            "storage_type": "Local Fallback Storage",
            "file_path": str(file_path),
            "download_url": f"/api/logs/download/{safe_filename}",
            "is_cloud": False,
            "size_bytes": len(content_bytes)
        }

    def save_report_pdf(self, report_filename: str, pdf_bytes: bytes) -> Dict[str, Any]:
        """Saves generated audit report PDF to Cloud Storage or local fallback."""
        if self.is_cloud_active and self.bucket is not None:
            try:
                blob = self.bucket.blob(f"reports/{report_filename}")
                blob.upload_from_string(pdf_bytes, content_type="application/pdf")
                blob.make_public()
                return {
                    "storage_type": "Firebase Cloud Storage",
                    "file_path": f"reports/{report_filename}",
                    "download_url": blob.public_url,
                    "is_cloud": True
                }
            except Exception as e:
                log.error(f"Cloud Storage report upload failed: {e}")
                raise RuntimeError(f"Cloud Storage report upload failed: {str(e)}")

        dest_path = self.local_storage_dir / "reports"
        dest_path.mkdir(parents=True, exist_ok=True)
        file_path = dest_path / report_filename
        with open(file_path, "wb") as f:
            f.write(pdf_bytes)

        return {
            "storage_type": "Local Fallback Storage",
            "file_path": str(file_path),
            "download_url": f"/api/reports/download/{report_filename}",
            "is_cloud": False
        }
