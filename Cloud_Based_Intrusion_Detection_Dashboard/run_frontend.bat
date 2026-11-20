@echo off
title SOC Intrusion Detection Frontend - React + Vite
echo ===================================================
echo Starting React + Vite SOC Security Dashboard...
echo ===================================================
set "PATH=C:\Users\Hp\AppData\Local\Programs\nodejs;%PATH%"
cd /d %~dp0frontend
call npm run dev
pause
