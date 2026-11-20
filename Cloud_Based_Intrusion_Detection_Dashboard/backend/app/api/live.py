from typing import List, Dict, Any
from fastapi import APIRouter, Query
from app.services.live_simulator import live_simulator
from app.database.db_service import db_service

router = APIRouter(prefix="/api/live", tags=["Live Monitoring"])

@router.get("/stream")
def get_live_stream_events(count: int = Query(5, ge=1, le=20)):
    """
    Returns latest stream events and optionally injects newly generated simulated demonstration records.
    Explicitly labeled as SIMULATED LIVE MONITORING.
    """
    # Fetch most recent logs from DB
    recent_logs = db_service.get_logs(page=1, page_size=count)["items"]
    recent_alerts = db_service.get_alerts(page=1, page_size=count)["items"]

    return {
        "mode": "SIMULATED LIVE MONITORING",
        "notice": "Simulated security events for demonstration and telemetry testing. Does not block host networking.",
        "recent_events": recent_logs,
        "recent_alerts": recent_alerts
    }

@router.post("/tick")
def trigger_live_telemetry_tick():
    """Generates a newly simulated security event on heartbeat to demonstrate real-time detection."""
    result = live_simulator.generate_event()
    return {
        "mode": "SIMULATED LIVE MONITORING",
        "generated_event": result["event"],
        "triggered_alert": result["alert"]
    }
