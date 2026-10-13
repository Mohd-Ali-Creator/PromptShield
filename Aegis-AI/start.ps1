# Aegis AI PowerShell Launcher
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Starting Aegis AI Services (PowerShell Launcher)" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

$root = $PSScriptRoot

# 1. Start Python Sidecar
Write-Host "[1/3] Starting Python ML Sidecar..." -ForegroundColor Green
$sidecarCmd = "Set-Location '$root\sidecar'; if (Test-Path '.\venv\Scripts\Activate.ps1') { & '.\venv\Scripts\Activate.ps1' }; python main.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $sidecarCmd

# 2. Start Gateway
Write-Host "[2/3] Starting Node Gateway..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\gateway'; node server.js"

# 3. Start Frontend
Write-Host "[3/3] Starting React Frontend..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\frontend'; npm run dev"

Write-Host ""
Write-Host "All Aegis AI services launched in separate windows!" -ForegroundColor Yellow
Write-Host "Open: http://localhost:5173" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
