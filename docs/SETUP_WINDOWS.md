# Sentinel AI V1.0 (Foundation) — Windows Setup & Execution Guide

This document provides step-by-step instructions for installing, configuring, testing, and running **Sentinel AI V1.0** on Windows operating systems using PowerShell or Command Prompt.

---

## 1. Prerequisites

Ensure you have the following installed on your Windows machine:
- **Python**: Version 3.11, 3.12, 3.13, or 3.14 (Ensure "Add Python to PATH" was checked during installation).
- **Node.js & npm**: Node.js v18+ (tested on v24.20.0 with npm 11.19.0).

Verify your environment by running in Windows PowerShell:
```powershell
python --version
node --version
npm.cmd --version
```

> [!NOTE]
> On Windows PowerShell, running unsigned `.ps1` scripts may be restricted by the default `ExecutionPolicy`. Use `npm.cmd` instead of `npm`, and run python scripts directly using `python -m ...`.

---

## 2. Environment Configuration

1. Open PowerShell and navigate to the project directory:
   ```powershell
   cd C:\Users\DEBASIS\Documents\Sentinel-AI
   ```

2. Copy the template configuration file:
   ```powershell
   Copy-Item .env.example .env
   ```

3. (Optional) Review the detection thresholds inside `.env`:
   - `BRUTE_FORCE_THRESHOLD=5` (Failed attempts within 60s)
   - `PORT_SCAN_THRESHOLD=5` (Distinct ports probed within 30s)
   - `DDOS_MIN_EVENTS=20` (Aggregate events within 30s from $\ge 3$ distinct source IPs)
   - `ANOMALOUS_SPIKE_THRESHOLD=20` (Single-source requests within 60s)

---

## 3. Backend Setup & Execution

### Option A: Direct Environment (Recommended if packages are already available)
```powershell
# 1. Install pinned backend dependencies
pip install -r requirements.txt

# 2. Verify/Initialize the SQLite database schema
python -c "from backend.app.database.session import init_db; init_db()"

# 3. Start the FastAPI development server
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Option B: Using a Dedicated Virtual Environment
```powershell
# 1. Create a virtual environment
python -m venv venv

# 2. Activate the virtual environment
powershell -ExecutionPolicy Bypass -File .\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the server
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend API will be accessible at:
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **ReDoc Documentation**: `http://127.0.0.1:8000/redoc`
- **Health Check**: `http://127.0.0.1:8000/health`

---

## 4. Frontend Setup & Execution

Open a **separate PowerShell terminal**:

```powershell
# 1. Navigate to frontend folder
cd C:\Users\DEBASIS\Documents\Sentinel-AI\frontend

# 2. Install node dependencies (using npm.cmd for Windows compatibility)
npm.cmd install

# 3. Start the Vite React development server
npm.cmd run dev
```

The dashboard will be accessible in your web browser at:
`http://localhost:5173`

The Vite dev server automatically proxies all `/api` requests to `http://127.0.0.1:8000`.

---

## 5. Running Automated Tests

To run the complete test suite (38 tests) across all modules:

```powershell
cd C:\Users\DEBASIS\Documents\Sentinel-AI
python -m pytest -v
```

To run individual test suites:
- **Detection Engine & Rules**: `python -m pytest tests/detection/test_phase2_detection.py -v`
- **API & REST Endpoints**: `python -m pytest tests/backend/test_api.py -v`
- **Phase 3 Validation**: `python -m pytest tests/backend/test_phase3_validation.py -v`
- **Database & Schemas**: `python -m pytest tests/backend/test_phase1_foundation.py -v`

---

## 6. Convenience One-Click Launchers (Batch Files)

For quick startup on Windows without typing commands:
- Double-click `start_sentinel.bat` in the project root to launch both the Backend Server and Frontend Dashboard simultaneously in separate terminal windows.
- Double-click `start_backend.bat` in the project root to start FastAPI on port 8000.
- Double-click `start_frontend.bat` in the project root to start the React dashboard on port 5173.

