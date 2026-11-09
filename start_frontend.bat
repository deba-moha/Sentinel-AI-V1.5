@echo off
setlocal
title Sentinel AI - SOC Frontend Dashboard

:: Always navigate to the frontend directory
cd /d "%~dp0frontend"

echo ================================================================
echo           SENTINEL AI V1.0 - FRONTEND DASHBOARD INITIALIZATION  
echo ================================================================

:: Check if Node.js / npm is available in PATH
where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js and npm were not found in your system PATH.
    echo Please install Node.js 18 or higher from https://nodejs.org/
    echo.
    pause
    exit /b 1
)

:: Check if node_modules folder exists
if not exist "%~dp0frontend\node_modules\" (
    echo [ERROR] Frontend dependencies are missing - node_modules directory not found.
    echo.
    echo To install the required frontend packages, please run:
    echo   cd frontend
    echo   npm install
    echo.
    pause
    exit /b 1
)

echo.
echo ================================================================
echo           SENTINEL AI V1.0 - SOC DASHBOARD RUNNING              
echo ================================================================
echo  * Frontend Application: http://localhost:5173
echo  * Backend API Target:   http://127.0.0.1:8000
echo  * Backend Swagger Docs: http://127.0.0.1:8000/docs
echo.
echo  Press Ctrl+C in this terminal window to stop the frontend.
echo ================================================================
echo.

call npm.cmd run dev

pause
