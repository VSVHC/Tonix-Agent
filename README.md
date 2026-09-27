<div align="center">

# 🛡️ Tonix Agent

**AI-powered black-box web application security scanner**

FastAPI backend · React/Vite dashboard · Playwright crawler · Ollama-powered finding enrichment

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](#requirements)
[![Node](https://img.shields.io/badge/node-18%2B-green)](#requirements)
[![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688)](#backend)
[![React](https://img.shields.io/badge/frontend-React%20%2B%20Vite-61DAFB)](#frontend)
[![Tests](https://img.shields.io/badge/tests-119%20passing-brightgreen)](#testing)
[![License](https://img.shields.io/badge/license-Unlicensed-lightgrey)](#license)

</div>

---

## Overview

Tonix Agent runs a real-browser crawl of a target application (via **Playwright**), then fans out **21 automated security test modules** across every discovered page — CORS, clickjacking, header hygiene, HTTP method abuse, request/response splitting, exposed `.git`, JS secret scanning, username enumeration, and more. Findings are enriched with a locally-run LLM (**Ollama**), streamed live to a React dashboard over WebSocket, and exportable as HTML/PDF reports. A standalone JWT testing toolkit and Slack alerting round out the workflow.

> ⚠️ **Authorized testing only.** Tonix Agent sends live requests to the target it's pointed at. Only run it against applications you own or are explicitly authorized to test.

---

## Features

| Category | Details |
|---|---|
| 🕷️ **Discovery** | Real Chromium crawl (Playwright) — waits for network idle, scrolls to trigger lazy-loaded chunks, and records every request the app actually fires, including runtime-built API calls |
| 🔍 **21 test modules** | See [Scan Modules](#scan-modules) below |
| 🤖 **LLM enrichment** | Local Ollama model (default `llama3.1:8b`) adds context/remediation to findings, with concurrent bounded enrichment |
| 🔑 **JWT toolkit** | Decode, weakness-check, and attach JWT findings straight into a scan report |
| 📊 **Live dashboard** | Real-time scan progress, sortable/filterable findings, module timing, analytics (KPIs, charts, history) |
| 📄 **Reporting** | On-demand HTML and PDF report generation |
| 🔔 **Notifications** | Slack webhook alerts on scan completion |
| 🔒 **Scope enforcement** | Requests outside the configured target scope are blocked before they're ever sent |
| 🧪 **Tested** | 119 unit tests across every module and the scope enforcer |

### Scan modules

`autocomplete` · `captcha` · `clickjacking` · `cors` · `crossdomain` · `directory_listing` · `error_exceptions` · `git_enum` · `headers` · `host_header` · `http_bypass` · `js_enum` · `req_splitting` · `res_splitting` · `robots` · `sitemap` · `trace` · `unencrypted_communication` · `username_enum` · `web_server`

---

## Architecture

```
                ┌──────────────────┐
                │  React Frontend  │  (Vite dev server, :3000)
                └────────┬─────────┘
                         │ REST + WebSocket
                ┌────────▼─────────┐
                │  FastAPI Backend │  (:8000)
                │  ── Orchestrator │
                │  ── Scope guard  │
                │  ── 21 modules   │
                └───┬────────┬─────┘
                    │        │
        ┌───────────▼─┐   ┌──▼────────────┐
        │  Playwright │   │  Ollama (LLM) │
        │  (Chromium) │   │  enrichment   │
        └─────────────┘   └───────────────┘
                    │
             ┌──────▼──────┐
             │   SQLite    │  (aiosqlite, WAL mode)
             └─────────────┘
```

---

## Requirements

| Component | Version |
|---|---|
| Python | 3.10+ |
| Node.js | 18+ |
| Ollama | Running locally, with a pulled model (default `llama3.1:8b`) |
| Playwright browsers | Installed via `playwright install chromium` (see below) |

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/<your-org>/tonix-agent.git
cd tonix-agent
```

### 2. Backend setup

```bash
# (recommended) create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# install Python dependencies
pip install -r backend/requirements.txt

# install the Chromium browser Playwright drives
playwright install chromium
```

### 3. Configure environment variables

```bash
cp env.example .env
```

Edit `.env` and set the values you need — see [Configuration](#configuration) below.

### 4. Start Ollama

Tonix Agent enriches findings with a local LLM. Install [Ollama](https://ollama.com), then pull the default model:

```bash
ollama pull llama3.1:8b
ollama serve
```

### 5. Run the backend

From the **project root**:

```bash
uvicorn backend.main:app --reload --port 8000
```

The API is now live at `http://localhost:8000` (interactive docs at `/docs`).

### 6. Frontend setup

```bash
cd frontend
npm install
npm run dev
```

The dashboard is now live at `http://localhost:3000`.

---

## Configuration

All configuration is read from `.env` (see `env.example`) and validated at startup via Pydantic.

| Variable | Default | Description |
|---|---|---|
| `SLACK_WEBHOOK_URL` | — | Slack incoming webhook URL; leave as the placeholder to disable Slack alerts |
| `SLACK_CHANNEL` | `#pentest-alerts` | Slack channel for notifications |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server address |
| `OLLAMA_MODEL` | `llama3.1:8b` | Model used for finding enrichment |
| `BACKEND_PORT` | `8000` | FastAPI server port |
| `FRONTEND_PORT` | `3000` | Vite dev server port |
| `ERROR_MODULE_RATE_LIMIT` | `5` | Requests/sec used by the error-disclosure module |
| `USERNAME_ENUM_KNOWN_ACCOUNT` | — | Optional known-valid account, improves username-enumeration accuracy |
| `DATABASE_PATH` | `./backend/database/pentest_agent.db` | SQLite database file |

Additional tunables (crawl concurrency, Playwright headless mode, page limits, scope subdomain rules) live in `backend/config.py`.

---

## Usage

1. Open the dashboard at `http://localhost:3000`.
2. Enter a target URL and launch a scan from **Dashboard**.
3. Watch progress live on **Live Scan** — findings stream in as each module completes.
4. Review historical scans on **History** and trends on **Analytics**.
5. Use **JWT Testing** to decode and probe tokens independently, and attach results to a report.
6. Download an HTML or PDF report from a completed scan.

### Key API endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scan/start` | Start a new scan |
| `POST` | `/api/scan/{id}/stop` \| `/pause` \| `/resume` | Control a running scan |
| `GET` | `/api/scan/history` | List all past scans |
| `GET` | `/api/scan/{id}` | Scan details + findings |
| `GET` | `/api/scan/{id}/findings` | Findings only |
| `DELETE` | `/api/scan/{id}` | Delete a scan |
| `GET` | `/api/report/{id}?format=pdf\|html` | Generate/download a report |
| `POST` | `/api/tools/jwt` | Analyze a JWT |
| `POST` | `/api/tools/attach` | Attach JWT findings to a scan |
| `GET` | `/api/health` | Ollama + database health check |
| `WS` | `/ws/{scan_id}` | Real-time scan event stream |

Full interactive documentation is available at `http://localhost:8000/docs` once the backend is running.

---

## Project structure

```
tonix-agent/
├── backend/
│   ├── main.py                 # FastAPI app, routes, WebSocket
│   ├── orchestrator.py         # ScanRunner / ScanFinaliser / ScanOrchestrator
│   ├── config.py               # Pydantic settings, validated from .env
│   ├── scope.py                # Scope enforcement (blocks out-of-scope requests)
│   ├── llm.py                  # Ollama integration
│   ├── logger.py                # Structured logging
│   ├── database/                # aiosqlite persistence layer
│   ├── modules/                 # 21 scan modules + Playwright crawler
│   ├── analysis/                # JWT decode / weakness toolkit
│   ├── notifications/           # Slack alerts
│   └── reports/                 # HTML/PDF report generation
├── frontend/
│   └── src/
│       ├── pages/                # Dashboard, LiveScan, History, Analytics, JwtTesting
│       ├── components/           # Sidebar, AddToReport, shared UI
│       └── lib/                  # API client, formatting, theme
├── tests/                        # 119 unit tests (pytest + respx)
├── env.example
└── pytest.ini
```

---

## Testing

```bash
pip install pytest pytest-asyncio respx
pytest
```

Run from the project root; `pytest.ini` picks up all 119 tests covering every scan module and the scope enforcer.

---

## Notes on the crawler

Tonix Agent crawls targets with a real headless browser (Playwright/Chromium) rather than a static/HTML crawler — this catches JavaScript-built API calls and lazy-loaded content that regex-based crawlers miss. If Chromium can't launch, the crawl fails with a clear error rather than silently falling back.

---

## License

No license file is currently included in this repository — add one (MIT, Apache-2.0, etc.) before distributing publicly.
