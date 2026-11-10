# Sentinel AI V1.5.0 — Release Notes

**Release:** 1.5.0  
**Project:** Sentinel AI  
**Release Type:** Hybrid Threat Detection Upgrade

---

## Overview

Sentinel AI V1.5 introduces machine-learning-based anomaly detection alongside the original deterministic rule-based detection engine.

The objective is to identify suspicious behavioural patterns in security telemetry while preserving the five original detection rules from V1.0.

---

## What's New

### 1. Hybrid Detection Engine
- Five original deterministic detection rules retained.
- Isolation Forest-based anomaly detection added.
- Independent rule-based and ML evaluation.
- Unified alert generation and persistence.
- ML detection can be disabled through configuration.

### 2. Machine Learning
- Isolation Forest with 100 estimators.
- Nine numerical input features.
- Reproducible synthetic training dataset.
- Model persistence using Joblib.
- Configurable anomaly threshold.
- Manual model training; no automatic training during application startup.

### 3. Dashboard Improvements
- Dedicated ML anomaly statistics.
- Rule-based versus ML alert breakdown.
- Detection-engine badges.
- Enhanced alert filtering.
- Updated hybrid detection timeline.
- Recent alerts with detection-engine identification.

### 4. Simulator Improvements
- Eight synthetic traffic scenarios.
- ML and deterministic detection operate on generated telemetry.
- Improved detection explanations and disclaimers.

### 5. Documentation and Setup
- Updated README and API specification.
- Windows setup instructions.
- Hybrid detection architecture documentation.
- Updated V1.5 branding and launch scripts.

---

## Technology Stack

**Backend:** Python, FastAPI, SQLAlchemy, SQLite  
**Machine Learning:** Scikit-learn, NumPy, Joblib  
**Frontend:** React, Vite, Tailwind CSS, Recharts  
**Testing:** Pytest  

---

## Verification Results

- Backend tests: 102 passed.
- Frontend production build: successful.
- ML model: successfully trained and loaded.
- All five deterministic rules: verified against V1.0.
- Fresh-install verification: passed.
- Missing-model fallback: verified.

---

## Important Limitations

- V1.5 currently operates on synthetic security telemetry.
- Isolation Forest scores represent behavioural deviation, not probabilities of malicious activity.
- ML anomaly attribution is statistical and does not establish the actual attacker.
- Challenging synthetic scenarios demonstrate false positives and missed subtle attacks.
- Real-time packet capture and production-scale monitoring are not included.

---

## Running Sentinel AI

1. Install the required Python and Node.js dependencies.
2. Train the ML model manually:
   ```powershell
   python -m backend.app.ml.train
   ```
3. Launch the application using:
   ```powershell
   .\start_sentinel.bat
   ```
4. Open the local dashboard:
   ```
   http://localhost:5173
   ```

---

## Release Scope

Sentinel AI V1.5.0 is intended as a locally operated hybrid security monitoring prototype and development project. It is not yet a production-ready enterprise SOC platform.

