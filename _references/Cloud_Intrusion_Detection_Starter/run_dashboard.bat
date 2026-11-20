@echo off
title Cloud-Based Intrusion Detection Dashboard
cd /d "%~dp0"
if exist "cloud_intrusion_detection_dashboard\app.py" (
    cd cloud_intrusion_detection_dashboard
)

echo Starting Cloud-Based Intrusion Detection Dashboard...
set "PATH=C:\Users\Hp\AppData\Local\Python\bin;C:\Users\Hp\AppData\Local\Python\pythoncore-3.15-64\Scripts;%PATH%"

python -m streamlit run app.py
if errorlevel 1 (
    "C:\Users\Hp\AppData\Local\Python\bin\python.exe" -m streamlit run app.py
)
pause
