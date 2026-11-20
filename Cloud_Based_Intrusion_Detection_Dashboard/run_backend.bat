@echo off
title SOC Intrusion Detection Backend - FastAPI
echo ===================================================
echo Starting Cloud-Based Intrusion Detection Backend...
echo ===================================================
set "PATH=C:\Users\Hp\AppData\Local\Python\bin;C:\Users\Hp\AppData\Local\Python\pythoncore-3.15-64\Scripts;%PATH%"
cd /d %~dp0backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
pause
