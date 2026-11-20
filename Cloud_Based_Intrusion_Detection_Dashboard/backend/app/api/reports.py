from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import FileResponse
from app.services.report_generator import report_generator
from app.database.db_service import db_service
import os

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.post("/generate")
def generate_security_report():
    """Generates an executive SOC audit report in PDF format and stores metadata."""
    try:
        report_data = report_generator.create_and_store_report()
        # Remove raw bytes from response payload
        report_data.pop("pdf_bytes", None)
        return {
            "success": True,
            "message": "Security Audit Report PDF successfully generated.",
            "report": report_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation error: {str(e)}")

@router.get("")
def list_reports():
    """Lists all previously compiled audit reports."""
    return {"items": db_service.get_reports()}

@router.get("/download/{filename}")
def download_report_file(filename: str):
    """Direct PDF download endpoint."""
    reports_dir = db_service.storage_service.local_storage_dir / "reports"
    file_path = reports_dir / filename
    if not file_path.exists():
        # Fallback: if not found, generate on the fly
        pdf_bytes = report_generator.generate_pdf()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type="application/pdf"
    )
