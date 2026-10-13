@echo off
echo ===================================================
echo Starting Aegis AI Services (CMD Launcher)
echo ===================================================

cd /d "%~dp0"

echo [1/3] Starting Python ML Sidecar...
start "Aegis Sidecar" cmd /k "cd /d "%~dp0sidecar" && .\venv\Scripts\activate.bat && python main.py"

echo [2/3] Starting Node Gateway...
start "Aegis Gateway" cmd /k "cd /d "%~dp0gateway" && node server.js"

echo [3/3] Starting React Frontend...
start "Aegis Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo All services launched!
echo Access the frontend at: http://localhost:5173
echo ===================================================
pause
