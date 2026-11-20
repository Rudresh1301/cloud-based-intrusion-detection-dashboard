import os
from pathlib import Path
from typing import List

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DOCS_DIR = BASE_DIR / "docs"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Application Config
APP_NAME: str = os.getenv("APP_NAME", "Cloud-Based Intrusion Detection Dashboard")
ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
DEBUG: bool = os.getenv("DEBUG", "true").lower() in ("true", "1", "yes")
PORT: int = int(os.getenv("PORT", 8000))
HOST: str = os.getenv("HOST", "0.0.0.0")

# CORS
cors_raw = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173")
CORS_ORIGINS: List[str] = [origin.strip() for origin in cors_raw.split(",") if origin.strip()]

# Database Settings
DATABASE_TYPE: str = os.getenv("DATABASE_TYPE", "sqlite")
SQLITE_DB_PATH: str = os.getenv("SQLITE_DB_PATH", str(DATA_DIR / "local_soc.db"))

# Firebase Configuration
FIREBASE_CREDENTIALS_PATH: str = os.getenv("FIREBASE_CREDENTIALS_PATH", "")
FIREBASE_PROJECT_ID: str = os.getenv("FIREBASE_PROJECT_ID", "")
FIREBASE_STORAGE_BUCKET: str = os.getenv("FIREBASE_STORAGE_BUCKET", "")

# Detection Thresholds
BRUTE_FORCE_THRESHOLD: int = int(os.getenv("BRUTE_FORCE_THRESHOLD", 5))
BRUTE_FORCE_CRITICAL: int = int(os.getenv("BRUTE_FORCE_CRITICAL", 10))
HIGH_VOLUME_THRESHOLD: int = int(os.getenv("HIGH_VOLUME_THRESHOLD", 50))
TIME_WINDOW_MINUTES: int = int(os.getenv("TIME_WINDOW_MINUTES", 10))

# Machine Learning
ML_CONTAMINATION: float = float(os.getenv("ML_CONTAMINATION", 0.1))
ML_MIN_SAMPLES: int = int(os.getenv("ML_MIN_SAMPLES", 10))
ML_RANDOM_STATE: int = int(os.getenv("ML_RANDOM_STATE", 42))

# Security
SECRET_KEY: str = os.getenv("SECRET_KEY", "soc-intrusion-cloud-secret-token-change-in-production")
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 1440))

# Mandatory Log Columns
REQUIRED_COLUMNS = ["timestamp", "source_ip", "username", "event_type", "status", "endpoint"]

# Sensitive endpoints probe patterns
SENSITIVE_ENDPOINTS = [
    "/admin", "/login", "/wp-admin", "/phpmyadmin", "/.env",
    "/config.php", "/api/v1/users", "/etc/passwd", "/actuator",
    "/server-status", "/console", "/debug"
]

# SOC UI Theme Colors
COLOR_RED = "#FF4560"
COLOR_ORANGE = "#FFB020"
COLOR_CYAN = "#00C8FF"
COLOR_GREEN = "#00D68F"
COLOR_PURPLE = "#8B5CF6"
COLOR_BLUE = "#087FE5"
