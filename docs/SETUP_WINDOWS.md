# Sentinel AI V1.5 — Windows Setup & Execution Guide

This document provides step-by-step instructions for installing, configuring, training, testing, and running **Sentinel AI V1.5 (Hybrid Threat Detection Platform)** on Windows operating systems using PowerShell or Command Prompt.

---

## 1. Prerequisites

Ensure you have the following installed on your Windows machine:
- **Python**: Version **3.12** recommended (Python 3.11, 3.12, or 3.13 64-bit; ensure "Add Python to PATH" was checked during installation).
- **Node.js & npm**: Node.js v18+ (tested on Node v20/v24 with npm).

Verify your environment by running in Windows PowerShell:
```powershell
python --version
node --version
npm.cmd --version
```

> [!NOTE]
> On Windows PowerShell, running unsigned `.ps1` scripts may be restricted by default. Use `npm.cmd` instead of `npm`, and run python scripts using `python -m ...`.

---

## 2. Environment Configuration

1. Open PowerShell and navigate to the project directory:
   ```powershell
   cd C:\Users\DEBASIS\Documents\Sentinel-AI-V1.5
   ```

2. Copy the template configuration files:
   ```powershell
   Copy-Item .env.example .env
   Copy-Item frontend\.env.example frontend\.env
   ```

3. (Optional) Review the detection thresholds inside `.env`:
   - `BRUTE_FORCE_THRESHOLD=5` (Failed attempts within 60s)
   - `PORT_SCAN_THRESHOLD=5` (Distinct ports probed within 30s)
   - `DDOS_MIN_EVENTS=20` (Aggregate events within 30s from $\ge 3$ distinct source IPs)
   - `ANOMALOUS_SPIKE_THRESHOLD=20` (Single-source requests within 60s)
   - `ENABLE_ML_DETECTION=True` (Enables unsupervised Isolation Forest anomaly scoring)
   - `ML_ANOMALY_THRESHOLD=-0.0200` (Scores $< -0.0200$ trigger anomaly incident)
   - `ML_WINDOW_SECONDS=60` (Sliding feature aggregation window)
   - `ML_MIN_EVENTS=5` (Minimum logs required before ML evaluation)

---

## 3. Backend Setup & Model Training

### Dedicated Virtual Environment (Recommended)

```powershell
# 1. Create a virtual environment
python -m venv venv

# 2. Activate the virtual environment
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1

# 3. Install pinned dependencies
python -m pip install -r requirements.txt

# 4. CRITICAL: Train the Isolation Forest Machine Learning model
python -m backend.app.ml.train
```

> [!IMPORTANT]
> The trained model artifact (`isolation_forest.joblib`) is intentionally excluded from Git.  
> Running `python -m backend.app.ml.train` generates `backend/app/ml/saved_models/isolation_forest.joblib` in under 2 seconds.  
> If you start the server without training the model, Sentinel AI continues operating normally with the 5 deterministic rules, but ML anomaly detection remains dormant.

### Starting the Backend Server Manually:
```powershell
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
cd C:\Users\DEBASIS\Documents\Sentinel-AI-V1.5\frontend

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

To run the complete test suite (**102 tests**) across backend, rules, ML subsystem, and API:

```powershell
cd C:\Users\DEBASIS\Documents\Sentinel-AI-V1.5
.\venv\Scripts\Activate.ps1
python -m pytest -v
```

To run individual test suites:
- **Hybrid Detection Engine**: `python -m pytest tests/detection/test_hybrid_detection_engine.py -v`
- **ML Anomaly Detection Rule**: `python -m pytest tests/detection/test_ml_rule_detection.py -v`
- **ML Features & Preprocessing**: `python -m pytest tests/ml/ -v`
- **Deterministic Rules & Deduplication**: `python -m pytest tests/detection/test_phase2_detection.py tests/detection/test_engine_deduplication.py -v`
- **API, Stats & Engine Filtering**: `python -m pytest tests/backend/test_api.py -v`

---

## 6. Convenience One-Click Launchers (Batch Files)

For everyday startup on Windows without typing commands:
- **`start_sentinel.bat`**: Double-click to launch both the Backend Server and Frontend Dashboard simultaneously in separate terminal windows.
- **`start_backend.bat`**: Double-click to start FastAPI on port 8000.
- **`start_frontend.bat`**: Double-click to start the React dashboard on port 5173.
