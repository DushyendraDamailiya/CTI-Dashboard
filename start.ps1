# Threat Intelligence Dashboard - PowerShell Startup Script
# Starts the Flask backend (port 5001) and local frontend server (port 8000)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Starting Threat Intelligence and Response Dashboard" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# Check Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[ERROR] Python is not found in PATH. Please install Python 3.10+" -ForegroundColor Red
    exit 1
}

# Create venv if needed
if (-not (Test-Path "venv")) {
    Write-Host "[INFO] Creating Python virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

# Activate venv if present
if (Test-Path "venv\Scripts\Activate.ps1") {
    & ".\venv\Scripts\Activate.ps1"
}

# Check requirements
Write-Host "[INFO] Checking Python dependencies..." -ForegroundColor Yellow
python -m pip install -q -r requirements.txt

# Ensure .env exists
if (-not (Test-Path ".env")) {
    Write-Host "[INFO] Creating .env from .env.example..." -ForegroundColor Yellow
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
    } else {
        New-Item ".env" -ItemType File | Out-Null
    }
}

# Start backend in a new window
Write-Host "[INFO] Starting Backend on http://localhost:5001 ..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ScriptDir'; if (Test-Path 'venv\Scripts\Activate.ps1') { & '.\venv\Scripts\Activate.ps1' }; python backend.py"

Start-Sleep -Seconds 2

# Start frontend in a new window
Write-Host "[INFO] Starting Frontend on http://localhost:8000 ..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ScriptDir'; python -m http.server 8000"

Start-Sleep -Seconds 1

# Start EDR agent in a new window
Write-Host "[INFO] Starting Windows EDR Agent ..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ScriptDir'; if (Test-Path 'venv\Scripts\Activate.ps1') { & '.\venv\Scripts\Activate.ps1' }; python windows_endpoint_agent.py"

Start-Sleep -Seconds 1

# Start Attack Detector in a new window
Write-Host "[INFO] Starting Real-Time Attack Detector ..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ScriptDir'; if (Test-Path 'venv\Scripts\Activate.ps1') { & '.\venv\Scripts\Activate.ps1' }; python attack_detector.py"

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Threat Intelligence Framework is running!" -ForegroundColor Cyan
Write-Host "- Frontend Dashboard: http://localhost:8000" -ForegroundColor White
Write-Host "- Backend API:        http://localhost:5001" -ForegroundColor White
Write-Host "- Backend Status:     http://localhost:5001/api/status" -ForegroundColor White
Write-Host "- Windows EDR Agent:  Active (Reporting to Backend)" -ForegroundColor White
Write-Host "- Attack Detector:    Active (Monitoring Logs)" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Opening web browser..." -ForegroundColor Yellow
Start-Process "http://localhost:8000"
