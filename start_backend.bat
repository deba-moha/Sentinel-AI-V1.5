@echo off
setlocal
title Sentinel AI - Backend Server

:: Always navigate to the repository root directory
cd /d "%~dp0"

echo ================================================================
echo           SENTINEL AI V1.0 - BACKEND SERVER INITIALIZATION      
echo ================================================================

:: Check if Python is installed on the host
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found in your system PATH.
    echo Please install Python 3.11 - 3.13 from https://www.python.org/
    echo Ensure you check the option to add Python to PATH during installation.
    echo.
    pause
    exit /b 1
)

:: Check for virtual environment
if exist "%~dp0venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment from .\venv ...
    call "%~dp0venv\Scripts\activate.bat"
) else (
    echo [WARNING] Virtual environment not found at .\venv
    echo Sentinel AI requires its dependencies to run.
    echo.
    echo If you have not created the virtual environment yet, please run:
    echo   python -m venv venv
    echo   venv\Scripts\pip install -r requirements.txt
    echo.
    echo Attempting to run with system Python...
)

:: Verify uvicorn availability
python -c "import uvicorn, fastapi, sqlalchemy, pydantic" >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Core backend dependencies are missing!
    echo Please install the required packages using:
    echo   pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

echo.
echo ================================================================
echo           SENTINEL AI V1.0 - BACKEND SERVER RUNNING             
echo ================================================================
echo  * Local API Service:    http://127.0.0.1:8000
echo  * Interactive Swagger:  http://127.0.0.1:8000/docs
echo  * ReDoc Documentation:  http://127.0.0.1:8000/redoc
echo  * Health Endpoint:      http://127.0.0.1:8000/health
echo.
echo  Press Ctrl+C in this terminal window to stop the server.
echo ================================================================
echo.

python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

pause
