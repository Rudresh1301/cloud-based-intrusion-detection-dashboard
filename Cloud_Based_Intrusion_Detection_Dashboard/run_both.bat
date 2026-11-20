@echo off
title SOC Dashboard Launcher
echo ========================================================
echo Launching Cloud-Based Intrusion Detection Dashboard...
echo ========================================================
start "SOC Backend (FastAPI)" cmd /c "%~dp0run_backend.bat"
timeout /t 2 /nobreak >nul
start "SOC Frontend (React Vite)" cmd /c "%~dp0run_frontend.bat"
echo Both services launched!
echo Frontend will be accessible at: http://localhost:3000
echo Backend API Docs accessible at:  http://localhost:8000/docs
