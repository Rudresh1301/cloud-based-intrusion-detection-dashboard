import os
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.core.config import APP_NAME, CORS_ORIGINS, DATA_DIR
from app.api import auth, dashboard, logs, threats, ip_intel, analytics, alerts, reports, health, settings, live
from app.services.log_processor import log_processor
from app.database.db_service import db_service

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup & shutdown events."""
    # Ensure sample data is seeded on initial run if database is fresh
    try:
        current_logs = db_service.get_logs(page=1, page_size=1)
        if current_logs["total"] == 0:
            sample_csv_path = DATA_DIR / "sample_logs.csv"
            if not sample_csv_path.exists():
                # Check root data dir
                alt_path = Path(__file__).resolve().parent.parent.parent / "data" / "sample_logs.csv"
                if alt_path.exists():
                    sample_csv_path = alt_path

            if sample_csv_path.exists():
                with open(sample_csv_path, "rb") as f:
                    content = f.read()
                log_processor.process_and_analyze(content, "sample_logs.csv")
                print(f"[*] Initialized SOC database with {sample_csv_path.name}")
    except Exception as e:
        print(f"[!] Startup seed notice: {e}")

    yield
    print("[*] Cloud Intrusion Detection Dashboard backend shutting down.")

app = FastAPI(
    title=APP_NAME,
    description="REST API Gateway for Cloud-Based Intrusion Detection Dashboard with Firebase BaaS integration.",
    version="2.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for flexible local & cloud development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(logs.router)
app.include_router(threats.router)
app.include_router(ip_intel.router)
app.include_router(analytics.router)
app.include_router(alerts.router)
app.include_router(reports.router)
app.include_router(health.router)
app.include_router(settings.router)
app.include_router(live.router)

@app.get("/")
def root():
    return {
        "app": APP_NAME,
        "status": "online",
        "version": "2.0.0",
        "docs_url": "/docs",
        "cloud_database": db_service.active_db_provider,
        "cloud_storage": db_service.active_storage_provider,
        "is_cloud_active": db_service.is_cloud_active
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
