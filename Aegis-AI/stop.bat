@echo off
echo Stopping Aegis AI services...
taskkill /f /im node.exe >nul 2>&1
taskkill /f /im python.exe >nul 2>&1
echo Done! All Node and Python processes terminated.
pause
