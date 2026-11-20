from typing import Dict, Any
from fastapi import APIRouter
from app.database.db_service import db_service
from app.schemas.schemas import SystemSettings
from app.core.config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_CRITICAL,
    HIGH_VOLUME_THRESHOLD,
    ML_CONTAMINATION,
    TIME_WINDOW_MINUTES
)

router = APIRouter(prefix="/api/settings", tags=["Settings"])

DEFAULT_CONFIG = {
    "brute_force_threshold": BRUTE_FORCE_THRESHOLD,
    "brute_force_critical": BRUTE_FORCE_CRITICAL,
    "high_volume_threshold": HIGH_VOLUME_THRESHOLD,
    "ml_contamination": ML_CONTAMINATION,
    "time_window_minutes": TIME_WINDOW_MINUTES,
    "auto_refresh_seconds": 15,
    "database_mode": "sqlite"
}

@router.get("")
def get_system_settings():
    """Retrieves active detection engine parameters and cloud configuration."""
    settings = db_service.get_setting("system_settings", DEFAULT_CONFIG)
    settings["is_cloud_active"] = db_service.is_cloud_active
    settings["active_database"] = db_service.active_db_provider
    settings["active_storage"] = db_service.active_storage_provider
    return settings

@router.post("")
def update_system_settings(settings: SystemSettings):
    """Updates operational thresholds and tuning parameters."""
    cfg = settings.model_dump()
    db_service.set_setting("system_settings", cfg)
    return {"message": "Settings updated successfully.", "settings": cfg}

@router.post("/clear-logs")
def clear_all_records():
    """Clears ingested security logs and reset threat alerts."""
    db_service.clear_all()
    return {"message": "All operational logs and security alerts cleared successfully."}
