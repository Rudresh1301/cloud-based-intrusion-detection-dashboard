from typing import Optional
from fastapi import APIRouter, Query, HTTPException, Body
from app.database.db_service import db_service
from app.schemas.schemas import AlertStatusUpdate

router = APIRouter(prefix="/api/alerts", tags=["Alerts Center"])

@router.get("")
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    severity: str = Query(""),
    status: str = Query(""),
    search: str = Query("")
):
    """Retrieves security alerts with stateful status, filters, and pagination."""
    return db_service.get_alerts(
        page=page,
        page_size=page_size,
        severity=severity,
        status=status,
        search=search
    )

@router.patch("/{alert_id}/status")
def update_alert_status(alert_id: str, update: AlertStatusUpdate):
    """Updates incident status (New -> Investigating -> Resolved) in Firestore / SQLite."""
    if update.status not in ["New", "Investigating", "Resolved", "Acknowledged"]:
        raise HTTPException(status_code=400, detail="Invalid alert status. Must be New, Investigating, Resolved, or Acknowledged.")

    success = db_service.update_alert_status(alert_id, update.status)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found or status unchanged.")

    return {"id": alert_id, "status": update.status, "message": "Alert status updated successfully."}
