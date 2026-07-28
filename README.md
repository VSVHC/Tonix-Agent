# Tonix Agent v2.0

AI-powered unauthenticated blackbox security scanner.
20 automated test modules + a Katana crawler for attack-surface discovery
+ a JWT testing toolkit + Ollama (llama3.1:8b) for finding enrichment.

**Requires the `katana` binary on PATH** (ProjectDiscovery). Every scan crawls
the target with Katana first, then runs the modules against what it finds.
Install: `go install github.com/projectdiscovery/katana/cmd/katana@latest`

---

## Setup

### 1. Backend

```bash
pip install -r backend/requirements.txt
cp env.example .env   # fill in your values
uvicorn backend.main:app --reload --port 8000   # run from project root
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev          # dev server on http://localhost:3000
```

### 3. Run tests

```bash
pip install pytest pytest-asyncio respx
pytest                # from project root
```

---

## Project Structure

```
pentest-agent/
├── env.example               ← Copy to .env and fill in values
├── .env                      ← Your local config (git-ignored)
├── pytest.ini                ← Test runner config
│
├── backend/
│   ├── main.py               ← FastAPI app, all API endpoints, WebSocket
│   ├── orchestrator.py       ← ScanRunner + ScanFinaliser + ScanOrchestrator
│   ├── config.py             ← Pydantic BaseSettings (validated from .env)
│   ├── logger.py             ← Structured logging (console + rotating file)
│   ├── models.py             ← All shared Pydantic models + WebSocket events
│   ├── scope.py              ← ScopeEnforcer (blocks out-of-scope requests)
│   ├── llm.py                ← Ollama integration, concurrent enrichment
│   ├── requirements.txt
│   │
│   ├── database/
│   │   └── db.py             ← Persistent aiosqlite connection, all DB helpers
│   │
│   ├── modules/              ← 20 scan modules + crawler
│   │   ├── base_module.py    ← Abstract base (shared httpx client)
│   │   ├── katana_crawler.py ← Katana discovery pipeline (runs before modules)
│   │   ├── autocomplete.py
│   │   ├── headers.py
│   │   ├── trace.py
│   │   ├── clickjacking.py
│   │   ├── cors.py
│   │   ├── host_header.py
│   │   ├── http_bypass.py
│   │   ├── unencrypted_communication.py
│   │   ├── error_exceptions.py
│   │   ├── git_enum.py
│   │   ├── web_server.py
│   │   ├── req_splitting.py
│   │   ├── res_splitting.py
│   │   ├── js_enum.py
│   │   ├── directory_listing.py
│   │   ├── username_enum.py
│   │   ├── captcha.py
│   │   ├── sitemap.py
│   │   ├── robots.py
│   │   └── crossdomain.py
│   │
│   ├── analysis/             ← JWT testing toolkit
│   │   ├── jwt_tool.py       ← JWT decode / weakness checks
│   │   └── attach.py         ← Attach JWT findings to a scan
│   │
│   ├── notifications/
│   │   └── slack.py          ← Slack webhook alerts
│   │
│   └── reports/
│       ├── build.py          ← Report assembly pipeline
│       ├── catalog.py        ← Finding catalog / metadata
│       ├── html_report.py    ← HTML report generation
│       └── pdf_generator.py  ← PDF report generation
│
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx
│       ├── App.jsx           ← Router, sidebar, health polling
│       ├── index.css         ← CSS variables, global tokens
│       ├── components/       ← Sidebar, AddToReport, shared ui.jsx
│       ├── lib/              ← api.js, format.js, testcases.js, theme.js
│       └── pages/
│           ├── Dashboard.jsx    ← Scan launcher + session stats
│           ├── LiveScan.jsx     ← Real-time scan view (sort/filter/progress)
│           ├── History.jsx      ← All past scans
│           ├── Analytics.jsx    ← Charts, KPIs, trends
│           └── JwtTesting.jsx   ← JWT decode & weakness testing
│
└── tests/
    ├── conftest.py           ← Shared fixtures (scope, scan_id, mock_client)
    ├── _helpers.py           ← mock_transport + shared test utilities
    ├── test_scope.py
    ├── test_attach_jwt.py
    ├── test_autocomplete.py
    ├── test_clickjacking.py
    ├── test_cors.py
    ├── test_crossdomain.py
    ├── test_directory_listing.py
    ├── test_error_exceptions.py
    ├── test_git_enum.py
    ├── test_headers.py
    ├── test_host_header.py
    ├── test_http_bypass.py
    ├── test_js_enum.py
    ├── test_req_splitting.py
    ├── test_res_splitting.py
    ├── test_sitemap_robots.py
    ├── test_trace.py
    ├── test_username_enum.py
    └── test_web_server.py
```

---

## What's New in v2.0

| Area | Change |
|------|--------|
| Config | Pydantic BaseSettings — validated at startup, clear errors |
| Logging | Structured logger — file + coloured console, rotating 10 MB × 5 |
| Database | Single persistent aiosqlite connection, WAL mode |
| HTTP client | Shared httpx.AsyncClient per scan — no connection leak |
| LLM | Concurrent enrichment via asyncio.gather (semaphore-bounded) |
| Orchestrator | Split into ScanRunner / ScanFinaliser / ScanOrchestrator |
| Security | CORS locked, rate limiting, UUID validation, path traversal guard |
| LiveScan UI | Sort + filter findings, % progress bar, module elapsed time |
| Analytics | New page — KPIs, bar/line/pie charts, scan history table |
| JWT | JWT testing toolkit (backend/analysis) + JwtTesting UI page |
| Reports | HTML + PDF report generation (build / catalog / html_report / pdf_generator) |
| Tests | 119 unit tests across all modules + scope enforcer |
