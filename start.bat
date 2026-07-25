@echo off
title Tonix Agent v2.0
cd /d "%~dp0"

echo.
echo  ============================================
echo       PENTEST AGENT v2.0 - STARTING UP
echo  ============================================
echo.
echo  Working directory: %CD%
echo.

:: ── Kill anything on ports 8000 / 3000 ───────────────
echo  Clearing ports...
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":8000 "') do taskkill /PID %%a /F >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":3000 "') do taskkill /PID %%a /F >nul 2>&1

:: ── Start Backend ─────────────────────────────────────
:: NOTE: --reload is intentionally removed. Uvicorn's WatchFiles reloader
:: can restart the server mid-scan and kill the running Katana subprocess.
:: Run without --reload for stable long scans.
echo  [1/2] Starting Backend...
start "Tonix Agent - Backend" cmd /k "cd /d %~dp0 && python -m uvicorn backend.main:app --port 8000"

echo  Waiting for backend...
timeout /t 4 /nobreak >nul

:: ── Start Frontend ────────────────────────────────────
echo  [2/2] Starting Frontend...
start "Tonix Agent - Frontend" cmd /k "cd /d %~dp0\frontend && npm run dev"

echo  Waiting for frontend...
timeout /t 6 /nobreak >nul

:: ── Open Browser ──────────────────────────────────────
echo  Opening browser...
start chrome "http://localhost:3000" 2>nul
if errorlevel 1 start "" "http://localhost:3000"

echo.
echo  ============================================
echo   RUNNING:  http://localhost:3000
echo  ============================================
echo.
echo  NOTE: Auto-reload is disabled (required for Katana on Windows).
echo  To apply backend changes: close the Backend window and run start.bat again.
echo.
echo  Keep the Backend and Frontend windows open.
echo  Close them to stop the agent.
echo.
pause
