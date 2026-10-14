# ThreatSense

**AI-Driven Network Threat Detection and Visualisation for SMBs**
VU Sydney · NIT3004 Final Project Delivery · Group 5 · Rabin Khadka (s8154766)

A monorepo with three parts: a **FastAPI backend** (ingestion, auth, detection
engine, alerting, AI reports), a **scikit-learn ML module** (Isolation Forest
training + the shared feature extractor), and a **React 18 + Chart.js frontend**
(the six screens). The submitted proposal is the source of truth for all specs.

> **The spine first.** A log should travel: *arrive → get scored → become a
> severity-tagged detection → show on the dashboard.* Everything below is
> organised so that loop is the first thing that works end-to-end.

---

## Layout

```
threatsense/
├── docker-compose.yml      # Postgres 16 + backend (built in task 0.3)
├── .env.example            # Postgres creds for compose
├── backend/                # Python 3.12 + FastAPI
│   ├── .env.example        # DB, JWT, SendGrid, OpenAI, Syslog config
│   ├── requirements.txt    # installs ml/ as an editable dep (-e ../ml)
│   ├── app/
│   │   ├── main.py         # entrypoint + /health
│   │   ├── config.py       # Pydantic settings from .env
│   │   ├── database.py     # SQLAlchemy 2.0 session
│   │   ├── models/         # ORM — one file per proposal table (9 total)
│   │   ├── schemas/        # Pydantic request/response models
│   │   ├── routers/        # the API surface (auth, sources, dashboard, …)
│   │   ├── middleware/     # JWT validation, rate limiting
│   │   ├── core/           # security helpers + tunable thresholds
│   │   └── services/       # the actual work:
│   │       ├── auth/       #   login, lockout, password reset
│   │       ├── ingestion/  #   Syslog listener + parser adapters
│   │       ├── detection/  #   engine, scheduler, severity, rules, model loader
│   │       ├── alerting/   #   async worker, SendGrid, retry/dedup
│   │       └── reporting/  #   OpenAI prompt → report → PDF
│   ├── db/                 # schema.sql + seed.py + migrations/
│   ├── scripts/            # syslog_sender.py (smoke test)
│   └── tests/
├── ml/                     # scikit-learn — "the heart of the project"
│   ├── features.py         # CANONICAL 10-feature extractor (shared w/ backend)
│   ├── train.py            # Isolation Forest (200 trees) → IF_v1.0
│   ├── evaluate.py         # precision/recall/F1 vs labelled attacks
│   ├── normalize.py        # score_samples → 0.0–1.0
│   ├── prepare_data.py     # CICIDS2017 / baseline prep (DECISION 1.9)
│   ├── data/{raw,processed}/   # datasets (gitignored)
│   └── models/             # saved model artifacts (gitignored)
├── frontend/               # React 18 + Chart.js (Vite)
│   ├── .env.example        # VITE_API_BASE_URL, poll interval
│   └── src/
│       ├── api/            # client w/ credentials:"include" (cookie auth)
│       ├── pages/          # the six screens
│       ├── charts/         # Chart.js wrappers
│       ├── components/     # notification bell, severity badge
│       └── styles/
├── docs/                   # accessibility checklist + operational notes
└── evidence/               # screenshots / terminal output for the final report
```

---

## Where each proposal component lives

### Backend — data layer

| Proposal | Location | Task |
|---|---|---|
| 9-table schema (Section 2) | `backend/db/schema.sql` | 1.1 |
| ORM models (1:1 with schema) | `backend/app/models/*.py` | 1.1 |
| Seed (SUPER_ADMIN, settings, config) | `backend/db/seed.py` | 1.2 |

### Backend — auth & API

| Proposal | Location | Task |
|---|---|---|
| Login / JWT-in-HttpOnly-cookie (UC 4.1) | `routers/auth.py` · `services/auth/` · `core/security.py` | 1.4 |
| Password reset (hashed token, 15-min) | `services/auth/reset.py` | 1.5 |
| JWT middleware + rate limiting | `middleware/auth.py` · `middleware/rate_limit.py` | 1.4 |
| Log-source CRUD (UC 4.2) | `routers/sources.py` | 1.8 |
| Dashboard read APIs (Sec 2.4) | `routers/dashboard.py` | 1.14 |
| Acknowledge endpoint (UC 4.6) | `routers/detections.py` | 1.14 |

### Backend — ingestion (Syslog)

| Proposal | Location | Task |
|---|---|---|
| RFC 5424 listener + buffered flush (Algo 1) | `services/ingestion/listener.py` | 1.6 |
| Parser adapters → `network_logs` fields | `services/ingestion/parsers/` | 1.7 |

### ML core + detection (the spine's brain)

| Proposal | Location | Task |
|---|---|---|
| 10 flow-window features (Algo 2) | **`ml/features.py`** | 1.11 |
| Isolation Forest training → `IF_v1.0` | `ml/train.py` · `ml/normalize.py` | 1.10 |
| Evaluation (P/R/F1) | `ml/evaluate.py` | 1.10 |
| Training-data prep (CICIDS2017) | `ml/prepare_data.py` | 1.9 |
| Detection engine + scheduler (Algo 2) | `services/detection/engine.py` · `scheduler.py` | 1.12 |
| Severity bands | `services/detection/severity.py` | 1.12 |
| Rule-based threat categorisation | `services/detection/rules.py` · `core/thresholds.py` | 1.13 |
| Model loading at inference | `services/detection/model.py` (imports `ml/`) | 1.12 |

> **Train/inference parity (the project's #1 risk).** The feature extractor lives
> in **one place** — `ml/features.py` — and is imported by *both* `ml/train.py`
> and the backend detection engine. The backend installs `ml/` as an editable
> package (`pip install -e ../ml`), so there is no second copy to drift out of
> sync. When you reach task 1.11, build the feature code here, not in the backend.

### Backend — alerting & reports

| Proposal | Location | Task |
|---|---|---|
| `alert_config` CRUD + test alert (Sec 2.5) | `routers/alerts.py` | 2.1 / 2.4 |
| Async worker: dedup, quiet-hours, 3× retry 2/4/8s (Algo 3, NFR-09) | `services/alerting/worker.py` | 2.3 |
| SendGrid client + email template | `services/alerting/sendgrid_client.py` · `templates/alert_email.html` | 2.3 |
| OpenAI 4-section report (Algo 5, UC 4.4) | `services/reporting/generator.py` · `prompt.py` | 3.2 |
| PDF export | `services/reporting/pdf.py` · `routers/reports.py` | 3.3 |
| Detection-settings + manual scan | `routers/settings.py` | 4.2 |

### Frontend — the six screens

| Screen (figure) | Location | Task |
|---|---|---|
| Login (Fig 3) | `src/pages/Login.jsx` | 1.15 |
| Dashboard (Fig 4) | `src/pages/Dashboard.jsx` + `src/charts/` | 1.16 |
| Log Sources (Fig 5) | `src/pages/LogSources.jsx` | 4.1 |
| Alert Configuration (Fig 6) | `src/pages/AlertConfig.jsx` | 2.4 |
| Detection Detail + Report (Fig 7) | `src/pages/DetectionDetail.jsx` | 3.4 |
| Detection Settings (Fig 8) | `src/pages/DetectionSettings.jsx` | 4.2 |

Auth is cookie-based: the API client sends `credentials:"include"` and **never**
stores the token in `localStorage`.

---

## Quick start

Full step-by-step instructions, including the Kali/Syslog setup and the attack
validation, are in the separately submitted **User Manual**. This is the short
version.

```bash
# 0. Environment templates — copy and fill in
cp .env.example .env
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env

# 1. Database (PostgreSQL 16 in Docker)
docker compose up -d

# 2. Backend
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # also installs ../ml as an editable package
                                         # schema is applied by db/schema.sql on first
                                         # container start — do NOT run db.seed here

# 3. TLS certificate for the syslog listener (not shipped — see below)
bash scripts/generate_dev_cert.sh

# 4. Run the four processes, each in its own terminal
uvicorn app.main:app --reload            # API           http://localhost:8000
python -m app.services.ingestion.listener # Syslog listener
python -m app.services.detection.engine   # Detection engine
python -m app.services.alerting.worker    # Alert worker

# 5. Frontend
cd ../frontend
npm install
npm run dev                              # http://localhost:5173
```

### Optional sample data — after the first administrator exists

`db.seed` is a development helper that loads a sample source and some example
log records. It is **not** part of installing ThreatSense.

Create your administrator first, through the first-run setup screen at
`http://localhost:5173` (User Manual, Section 10). If the `administrators`
table is empty when `db.seed` runs, the script creates a SUPER_ADMIN of its own
with a well-known default password, which closes the setup screen and leaves a
privileged development account in your database.

Once your own administrator exists, the seed is safe to run and reuses that
account rather than creating a second one:

```bash
cd backend && source .venv/bin/activate
python -m db.seed
```

### Tests

```bash
cd backend && source .venv/bin/activate && pytest tests/ -q
cd ../frontend && npm run build
```

The backend suite runs against a real PostgreSQL instance rather than an
in-memory substitute, so schema constraints, foreign keys and transaction
behaviour are genuinely exercised. SendGrid and OpenAI are forced to mock
clients for every test (`tests/conftest.py`), so the suite never sends email,
never calls a paid API and never depends on the network.

### TLS certificates are not included

`backend/certs/` is excluded from this submission: a TLS private key should not
ship inside a code archive. `scripts/generate_dev_cert.sh` regenerates the
development pair in one command (step 3 above). To run without TLS entirely,
set `SYSLOG_TLS_ENABLED=false` in `backend/.env` — note that this disables the
encrypted transport NFR-04 requires.

### Secrets

No `.env` file is included and no API key appears anywhere in this archive.
Only `*.env.example` templates are shipped. `SENDGRID_API_KEY` and
`OPENAI_API_KEY` are optional: with neither set, both integrations fall back to
mock clients and the whole system runs offline.

## Supporting documents in this archive

| File | Contents |
|---|---|
| `FINAL_CODE_STATE.md` | Every major feature, marked PRESENT / PARTIAL / MISSING against the approved proposal, with the source evidence for each |
| `KNOWN_LIMITATIONS.md` | The ten differences from the proposal that are documented rather than resolved, each with the reason and what closing it would take |
| `FINAL_LOCAL_VALIDATION.md` | Which commands were run, their results, and what still needs a live environment |

## Architecture

Four cooperating processes plus PostgreSQL 16. The API, syslog listener,
detection engine and alert worker run independently so that a slow database
write or a failing email provider cannot stall syslog reception.

A log travels: **arrive → get scored → become a severity-tagged detection →
show on the dashboard → dispatch an alert → become an AI incident report.**
