from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Query, HTTPException
from app.database.db_service import db_service

router = APIRouter(prefix="/api/ip-intelligence", tags=["IP Intelligence"])

@router.get("")
def list_ip_intelligence(
    search: str = Query(""),
    threat_status: str = Query(""),
    min_risk: int = Query(0, ge=0, le=100)
):
    """Retrieves correlated IP threat profiles with geographic and ISP intelligence."""
    ips = db_service.get_ip_intel_list(search=search, threat_status=threat_status)
    if min_risk > 0:
        ips = [ip for ip in ips if ip.get("risk_score", 0) >= min_risk]
    return {"items": ips, "total": len(ips)}

@router.get("/{ip_address}")
def get_ip_profile(ip_address: str):
    """Returns detailed forensic intelligence profile for a specific IP."""
    ips = db_service.get_ip_intel_list(search=ip_address)
    matched = next((i for i in ips if i["ip_address"] == ip_address), None)
    if not matched:
        raise HTTPException(status_code=404, detail="IP address profile not found.")

    # Get recent security events from this IP
    logs = db_service.get_logs(page=1, page_size=20, search=ip_address)["items"]
    alerts = db_service.get_alerts(page=1, page_size=20, search=ip_address)["items"]

    return {
        "profile": matched,
        "recent_logs": logs,
        "triggered_alerts": alerts,
        "is_reputation_bad": matched.get("risk_score", 0) >= 50
    }
