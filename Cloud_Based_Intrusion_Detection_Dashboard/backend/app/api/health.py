from fastapi import APIRouter
from app.database.db_service import db_service

router = APIRouter(prefix="/api/health", tags=["Cloud Health"])

@router.get("")
def get_cloud_services_health():
    """Real health checks for Cloud Services (Firestore, Storage, Auth, Backend API)."""
    return db_service.get_cloud_health()
