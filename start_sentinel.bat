@echo off
setlocal
title Sentinel AI - Launch Controller

:: Navigate to repository root directory
cd /d "%~dp0"

echo ================================================================
echo           SENTINEL AI V1.0 - LAUNCH CONTROLLER                  
echo ================================================================
echo.
echo  Starting Sentinel AI V1.0 Platform:
echo   - Backend API Server: FastAPI on port 8000
echo   - SOC Dashboard: React and Vite on port 5173
echo.
echo ================================================================
echo  * Frontend SOC Dashboard: http://localhost:5173
echo  * Backend API Service:    http://127.0.0.1:8000
echo  * Interactive Swagger:    http://127.0.0.1:8000/docs
echo  * Health Endpoint:        http://127.0.0.1:8000/health
echo ================================================================
echo.

:: Check prerequisites
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in system PATH. Cannot launch backend.
    pause
    exit /b 1
)

where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js or npm not found in system PATH. Cannot launch frontend.
    pause
    exit /b 1
)

:: Check if frontend node_modules exists
if not exist "%~dp0frontend\node_modules\" (
    echo [WARNING] Frontend dependencies are missing - node_modules not found.
    echo Please run npm install inside the frontend folder before launching.
    echo.
    pause
    exit /b 1
)

echo [*] Launching Backend Server in a new window...
start "Sentinel AI - Backend Server" cmd /k "call "%~dp0start_backend.bat""

:: Short pause to give backend time to initialize before starting frontend
timeout /t 2 /nobreak >nul

echo [*] Launching Frontend Dashboard in a new window...
start "Sentinel AI - Frontend SOC" cmd /k "call "%~dp0start_frontend.bat""

echo.
echo [SUCCESS] Both Sentinel AI services have been launched!
echo Check the individual terminal windows for live server logs.
echo You may close this launcher window at any time.
echo.
pause
