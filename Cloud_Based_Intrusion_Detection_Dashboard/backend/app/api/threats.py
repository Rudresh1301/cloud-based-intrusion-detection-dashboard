from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Query, HTTPException
from app.database.db_service import db_service

router = APIRouter(prefix="/api/threats", tags=["Threat Analysis"])

@router.get("")
def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    severity: str = Query(""),
    attack_category: str = Query(""),
    source_ip: str = Query(""),
    search: str = Query("")
):
    """Retrieves threat incidents with multi-faceted filtering and pagination."""
    alerts_data = db_service.get_alerts(
        page=page,
        page_size=page_size,
        severity=severity,
        search=search or source_ip or attack_category
    )

    items = alerts_data["items"]
    if attack_category and attack_category.lower() != "all":
        items = [i for i in items if attack_category.lower() in str(i.get("alert_type", "")).lower()]

    return {
        "items": items,
        "total": alerts_data["total"],
        "page": page,
        "page_size": page_size
    }

@router.get("/summary")
def get_threat_summary():
    """Returns high-level threat metrics for the Threat Analysis dashboard header."""
    alerts = db_service.get_alerts(page=1, page_size=2000)["items"]
    
    crit_count = sum(1 for a in alerts if a.get("severity") == "Critical")
    high_count = sum(1 for a in alerts if a.get("severity") == "High")
    med_count = sum(1 for a in alerts if a.get("severity") == "Medium")
    low_count = sum(1 for a in alerts if a.get("severity") == "Low")

    rule_count = sum(1 for a in alerts if a.get("detection_method") == "rule-based")
    ml_count = sum(1 for a in alerts if "ml" in str(a.get("detection_method", "")).lower())

    return {
        "total_threats": len(alerts),
        "critical_threats": crit_count,
        "high_threats": high_count,
        "medium_threats": med_count,
        "low_threats": low_count,
        "rule_based_detections": rule_count,
        "ml_anomaly_detections": ml_count,
    }

@router.get("/{threat_id}")
def get_threat_detail(threat_id: str):
    """Returns comprehensive drill-down details and forensic evidence for a specific incident."""
    alerts = db_service.get_alerts(page=1, page_size=2000)["items"]
    matched = next((a for a in alerts if a["id"] == threat_id), None)
    if not matched:
        raise HTTPException(status_code=404, detail="Threat incident not found.")

    # Retrieve related raw logs for this source IP
    source_ip = matched.get("source_ip", "")
    related_logs = []
    if source_ip:
        related_logs = db_service.get_logs(page=1, page_size=15, search=source_ip)["items"]

    return {
        "threat": matched,
        "related_events": related_logs,
        "mitigation_playbook": {
            "immediate_action": matched.get("recommended_action", "Apply IP rate-limiting at firewall perimeter."),
            "containment_step": "Isolate user session tokens; force re-authentication for affected credentials.",
            "post_incident_audit": "Perform log audit across adjacent timestamps to trace lateral reconnaissance."
        }
    }
