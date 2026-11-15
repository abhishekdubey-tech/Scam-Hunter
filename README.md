# SCAM HUNTER

**Detect. Investigate. Protect.**

SCAM HUNTER is a fraud investigation workstation for reviewing suspicious messages, URLs, and screenshots. It surfaces concrete warning signs, explains manipulation tactics, and offers practical next steps. The app is designed to work in a local deterministic demo mode without an AI key.

## What it does

- Message and static URL analysis with explainable heuristic indicators
- Screenshot text extraction through Tesseract OCR (when installed)
- Separate risk score and confidence fields, evidence, Scam DNA, and recommendations
- SQLite investigation history and real workspace counts
- Situation-specific “What if I clicked?” guidance, including India’s 1930 helpline and official reporting portal
- Responsive dark investigation workspace and demo examples
- Public landing story with a signal map, evidence walkthrough, and reduced-motion support
- Optional Google GenAI structured analysis with evidence-quote grounding

## Architecture

```text
frontend/   React + Vite interface
backend/    FastAPI API, Pydantic response models, SQLite persistence, OCR endpoint
```

The deterministic detector always runs first. When `GEMINI_API_KEY` is set in the root `.env`, the backend also requests structured Gemini findings, validates them with Pydantic, and accepts quoted evidence only when it appears in the submitted text. New grounded signals are capped during risk aggregation. If the API is unavailable or its response is malformed, the API safely returns deterministic analysis. The key stays server-side.

## Run locally

### Backend

```powershell
Copy-Item .env.example .env
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

API docs are served at `http://127.0.0.1:8000/docs`.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL (normally `http://localhost:5173`). The backend uses SQLite at `backend/scam_hunter.db` by default. Set `SCAM_HUNTER_DB` to override it.

## Publish a demo to Vercel

Import this project folder into Vercel or run `npx vercel --prod` from the repository root. The root `vercel.json` builds `frontend/` and publishes `frontend/dist/`. The public frontend includes deterministic in-browser demo analysis when no API is available. In this static deployment, SQLite history, Gemini, screenshot OCR, and PDF generation are unavailable; they require a separately hosted backend and persistent database. Do not set a Gemini key in Vite or any `VITE_*` variable because those values are exposed to the browser.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Service and demo-mode status |
| POST | `/api/analyze/message` | Analyze submitted text (`{"content":"..."}`) |
| POST | `/api/analyze/url` | Static URL structure inspection (`{"url":"https://..."}`); never fetches the host |
| POST | `/api/analyze/screenshot` | OCR and analyze PNG/JPG/WEBP multipart upload (8 MB limit) |
| GET | `/api/history` | List saved cases; optional `q` and `risk` filters |
| GET | `/api/history/{id}` | Read a saved report |
| GET | `/api/history/{id}/report.pdf` | Download a generated investigation PDF |
| DELETE | `/api/history/{id}` | Delete one saved case |
| DELETE | `/api/history` | Clear saved cases (the app asks for confirmation) |
| GET | `/api/dashboard/stats` | Counts and recent cases derived from SQLite |

## Privacy and security

The local API does not retain submitted text in saved history by default. Set `STORE_SUBMITTED_CONTENT=true` to opt in to storing raw content inside SQLite reports. Keep the database on a trusted device and delete it to remove local history. The app does not fetch submitted URLs, execute uploaded content, or store API keys in the browser. CORS is restricted to local Vite origins by default. OCR requires the Tesseract system executable as well as the Python package.

When Gemini is configured, submitted text is sent from the backend to Google for analysis. The API key is read from the root `.env`; the browser never receives it. Gemini findings are schema-validated and evidence is kept only when its quote matches the submitted text. Deterministic results remain available without Gemini.

Risk bands are heuristic categories, not statistical probabilities or proof of fraud. No domain reputation provider or live identity verification is configured. The emergency assistant provides advice only; it cannot contact a bank or police, and cannot reverse a transaction.

## Future scope

- Rate limiting and authentication for hosted deployment
- Trusted domain reputation provider with safe request controls

## Screenshots

Run the frontend locally to view the landing page, investigation workspace, evidence report, case history, and emergency assistant.

## Brand assets

The current geometric search mark is embedded in the interface and available as `frontend/public/favicon.svg`.
