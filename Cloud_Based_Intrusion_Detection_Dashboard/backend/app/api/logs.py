import io
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, Query, HTTPException, Response
from fastapi.responses import FileResponse, StreamingResponse
import pandas as pd

from app.services.log_processor import log_processor
from app.database.db_service import db_service

router = APIRouter(prefix="/api/logs", tags=["Security Logs"])

@router.post("/validate")
async def validate_log_file(file: UploadFile = File(...)):
    """Validates uploaded log file schema, checks duplicates and syntax without executing analysis."""
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    
    # 50MB max limit
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds maximum 50MB limit.")

    try:
        df, validation = log_processor.parse_file(content, file.filename)
        return {
            "filename": file.filename,
            "size_bytes": len(content),
            "validation": validation
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Validation failed: {str(e)}")

@router.post("/upload")
async def upload_and_process_logs(file: UploadFile = File(...)):
    """Uploads file to Cloud Storage, executes detection engine, and commits records."""
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        result = log_processor.process_and_analyze(content, file.filename)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log analysis processing failed: {str(e)}")

@router.get("")
def get_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: str = Query(""),
    classification: str = Query("")
):
    """Retrieves paginated, filtered security log records."""
    return db_service.get_logs(page=page, page_size=page_size, search=search, classification=classification)

@router.get("/export")
def export_logs_csv(search: str = Query(""), classification: str = Query("")):
    """Exports processed security logs as a downloadable CSV."""
    logs_data = db_service.get_logs(page=1, page_size=10000, search=search, classification=classification)
    items = logs_data["items"]
    if not items:
        return Response(content="timestamp,source_ip,username,event_type,status,endpoint,classification\n", media_type="text/csv")

    df = pd.DataFrame(items)
    cols_to_export = ["timestamp", "source_ip", "username", "event_type", "status", "endpoint", "classification", "risk_score"]
    export_df = df[[c for c in cols_to_export if c in df.columns]]

    stream = io.StringIO()
    export_df.to_csv(stream, index=False)
    
    return Response(
        content=stream.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=soc_security_logs_export.csv"}
    )
