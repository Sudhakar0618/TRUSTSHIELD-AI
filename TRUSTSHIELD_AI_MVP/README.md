# TRUSTSHIELD AI MVP

Starter project: FastAPI backend + React/Vite frontend.

## Backend (PowerShell terminal 1)
```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload
```
API: http://127.0.0.1:8000 — Docs: http://127.0.0.1:8000/docs

If activation is blocked:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
Then activate again.

## Frontend (PowerShell terminal 2, from project root)
```powershell
cd frontend
npm install
npm run dev
```
Open the localhost URL printed by Vite (normally http://localhost:5173).

This is an educational heuristic prototype, not proof that a website is safe or malicious. Never enter passwords or sensitive URLs.
