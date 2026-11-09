# Sentinel AI V1.0 — Manual GitHub Web Upload Guide

This guide is specifically written for beginners who manage their code through GitHub's web interface without running Git commands in the terminal.

---

## 1. What to Upload vs. What to Exclude

When uploading your project to GitHub through the website, you should **only upload source code, documentation, and configuration templates**. 

### ✅ Files and Folders to Upload:
- `backend/` (All source code: `app/`, `core/`, `detection/`, `services/`, etc.)
- `frontend/` (Source files: `src/`, `public/`, `package.json`, `package-lock.json`, `vite.config.js`, `tailwind.config.js`, `postcss.config.js`, `index.html`, `.env.example`)
- `tests/` (All test suites: `backend/`, `detection/`, `conftest.py`)
- `docs/` (`API_SPECIFICATION.md`, `SETUP_WINDOWS.md`, `GITHUB_UPLOAD_GUIDE.md`)
- `requirements.txt` (Pinned backend Python dependencies)
- `.env.example` (Root environment configuration template)
- `.gitignore` (Git ignore rules for tools and developers)
- `README.md` (Project overview and full documentation)
- `start_backend.bat` (Windows backend startup script)
- `start_frontend.bat` (Windows frontend startup script)
- `start_sentinel.bat` (Windows joint launcher script)

### ❌ DO NOT Upload (Excluded Items):
- `venv/` or `.venv/` (Local Python virtual environment — heavy and system-dependent)
- `frontend/node_modules/` (Local Node.js libraries — heavy and installed via `npm install`)
- `frontend/dist/` (Compiled production artifacts — regenerated via `npm run build`)
- `frontend/.vite/` (Vite cache)
- `.env` or `frontend/.env` (Local environment variables — may contain machine-specific paths)
- `sentinel.db`, `*.sqlite`, `*.db` (Local SQLite databases — regenerated automatically on launch)
- `__pycache__/` or `*.pyc` (Compiled Python bytecode)
- `.pytest_cache/` (Pytest temporary cache)

---

## 2. Step-by-Step Manual Upload Instructions

### Step 1: Create a New Repository on GitHub
1. Open your web browser and navigate to [GitHub](https://github.com/).
2. Log in to your GitHub account.
3. Click the **+** (plus icon) in the top-right corner and select **New repository**.
4. Enter your repository name: `Sentinel-AI` (or `sentinel-ai`).
5. Choose **Public** or **Private**.
6. **Important**: Under *"Initialize this repository with"*, leave all checkboxes **unchecked** (do NOT check "Add a README file", do NOT check ".gitignore template", do NOT check "Choose a license") because our project already includes complete versions of these files.
7. Click **Create repository**.

### Step 2: Upload Project Files via Web Browser
1. On the new repository page, click the link that says **"uploading an existing file"**.
2. Open Windows File Explorer and navigate to your project folder:
   `C:\Users\DEBASIS\Documents\Sentinel-AI`
3. Drag and drop the approved files and folders (e.g., `backend`, `docs`, `tests`, `requirements.txt`, `README.md`, `.gitignore`, `.env.example`, `.bat` files) into the GitHub dropzone.
4. For the `frontend` directory:
   - Ensure you do NOT include `frontend/node_modules/` or `frontend/dist/`.
   - Drag the `frontend` folder (containing `src`, `package.json`, etc.) into GitHub.
5. In the **Commit changes** box at the bottom of the page:
   - Enter a title: `Initial release: Sentinel AI V1.0 (Foundation)`
   - Enter an optional description: `V1.0 deterministic detection engine, synthetic telemetry simulator, REST API, and SOC dashboard.`
   - Keep "Commit directly to the main branch" selected.
6. Click **Commit changes**.

> [!TIP]
> If GitHub's web interface limits the number of files in a single drag-and-drop batch (typically up to 100 files per upload), you can upload in 2-3 smaller batches:
> 1. Batch 1: Root files (`README.md`, `requirements.txt`, `.gitignore`, `.env.example`, `.bat` files) and `docs/`.
> 2. Batch 2: `backend/` and `tests/`.
> 3. Batch 3: `frontend/` (without `node_modules` and `dist`).

---

## 3. How Other Users / Evaluators Run Your Repository

When someone downloads or clones your repository from GitHub, they can run Sentinel AI V1.0 in 4 simple steps:

1. **Download and Extract**:
   Click **Code** -> **Download ZIP** on GitHub and extract the folder.

2. **Configure Environment**:
   Copy `.env.example` to `.env` in the root folder and inside `frontend/` if needed.

3. **Install Dependencies**:
   - Backend:
     ```powershell
     python -m venv venv
     venv\Scripts\pip install -r requirements.txt
     ```
   - Frontend:
     ```powershell
     cd frontend
     npm install
     cd ..
     ```

4. **Launch**:
   Double-click `start_sentinel.bat` or run:
   - `start_backend.bat` in one window.
   - `start_frontend.bat` in a second window.

Access the dashboard at `http://localhost:5173` and Swagger API docs at `http://127.0.0.1:8000/docs`.

