@echo off
title SOC Backend Pytest Suite
echo ========================================================
echo Running Backend Threat Detection & API Test Suite...
echo ========================================================
set "PATH=C:\Users\Hp\AppData\Local\Python\bin;C:\Users\Hp\AppData\Local\Python\pythoncore-3.15-64\Scripts;%PATH%"
cd /d %~dp0
python -m pytest tests/test_api_and_detection.py -v
pause
