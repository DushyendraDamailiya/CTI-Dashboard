@echo off
setlocal enabledelayedexpansion

REM Threat Intelligence Dashboard - Windows Startup Script
REM Starts the Flask backend (port 5001) and local frontend server (port 8000)

cd /d "%~dp0"
title Threat Intelligence Dashboard

echo ========================================================
echo Starting Threat Intelligence and Response Dashboard
echo ========================================================

REM Check Python installation
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

REM Check or create virtual environment
if not exist "venv" (
    echo [INFO] Creating Python virtual environment...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

REM Activate virtual environment
if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
)

REM Install dependencies
echo [INFO] Checking Python dependencies...
python -m pip install -q -r requirements.txt

REM Ensure .env exists
if not exist ".env" (
    echo [INFO] Creating .env from .env.example...
    if exist ".env.example" (
        copy ".env.example" ".env" >nul
    ) else (
        type nul > ".env"
    )
)

echo [INFO] Starting Backend on http://localhost:5001 ...
start "Threat Dashboard - Backend (5001)" cmd /c "python backend.py"

REM Give backend a moment to initialize
timeout /t 2 /nobreak >nul

echo [INFO] Starting Frontend on http://localhost:8000 ...
start "Threat Dashboard - Frontend (8000)" cmd /c "python -m http.server 8000"

timeout /t 1 /nobreak >nul

echo [INFO] Starting Windows EDR Agent ...
start "Threat Dashboard - EDR Agent" cmd /c "python windows_endpoint_agent.py"

echo [INFO] Starting Real-Time Attack Detector ...
start "Threat Dashboard - Attack Detector" cmd /c "python attack_detector.py"

echo.
echo ========================================================
echo Threat Intelligence Framework is running!
echo - Frontend Dashboard: http://localhost:8000
echo - Backend API:        http://localhost:5001
echo - Backend Status:     http://localhost:5001/api/status
echo - Windows EDR Agent:  Active (Reporting to Backend)
echo - Attack Detector:    Active (Monitoring Logs)
echo ========================================================
echo.
echo Opening browser...
start http://localhost:8000

echo Close the opened command windows to stop the services.
