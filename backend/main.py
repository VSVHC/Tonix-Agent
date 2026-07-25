"""
main.py
───────
FastAPI application entry point.

Security improvements over v1:
  - CORS locked to known origins only (no wildcard)
  - Rate limiting on POST /api/scan/start (SlowAPI)
  - Input validation on all path params (UUID format enforced)
  - scan_id validated as UUID before any DB/orchestrator lookup
  - Trusted host middleware for Host header injection prevention

Endpoints:
  POST /api/scan/start          → start a new scan
  GET  /api/scan/history        → list all past scans
  GET  /api/scan/{id}           → get scan + findings
  GET  /api/scan/{id}/findings  → findings only
  GET  /api/report/{id}         → download report (pdf | html), built on demand
  POST /api/scan/{id}/stop      → stop a running scan
  POST /api/scan/{id}/pause     → pause between modules
  POST /api/scan/{id}/resume    → resume a paused scan
  DELETE /api/scan/{id}         → delete scan from DB
  GET  /api/health              → Ollama + DB health
  WS   /ws/{scan_id}            → real-time event stream
"""

import re
import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from starlette.background import BackgroundTask
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from backend.config import settings
from backend.logger import configure_logging, get_logger
from backend.models import (
    ScanRequest, ScanResponse, ScanStatus, WSEvent,
    JwtAnalyzeRequest, AttachToReportRequest,
)
from backend.database.db import (
    init_db, close_db, check_db_health,
    get_all_scans, get_scan_by_id, get_findings_by_scan, deduplicate_findings,
    delete_scan_by_id, save_finding, delete_findings_by_scan_and_module,
    update_scan_counts,
)
from backend.orchestrator import ScanOrchestrator
from backend.llm import check_ollama_health
from backend.analysis.jwt_tool import analyze_jwt
from backend.analysis.attach import build_findings
from backend.reports.build import build_report, count_by_severity

# ── Logging: must be first ────────────────────────────────
configure_logging(
    level=settings.LOG_LEVEL,
    log_dir=settings.LOG_DIR,
    max_bytes=settings.LOG_MAX_BYTES,
    backup_count=settings.LOG_BACKUP_COUNT,
)
log = get_logger(__name__)

# ── Rate limiter ──────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── UUID validation regex ─────────────────────────────────
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _validate_scan_id(scan_id: str) -> str:
    """Raise 400 immediately if scan_id is not a valid UUID."""
    if not _UUID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    return scan_id


# ─────────────────────────────────────────────────────────
#  WebSocket connection manager
# ─────────────────────────────────────────────────────────

class ConnectionManager:
    """Manages all active WebSocket connections per scan."""

    def __init__(self) -> None:
        self._connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, scan_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.setdefault(scan_id, set()).add(ws)
        log.debug("WS connected: scan=%s", scan_id)

    def disconnect(self, scan_id: str, ws: WebSocket) -> None:
        if scan_id in self._connections:
            self._connections[scan_id].discard(ws)

    async def broadcast(self, event: WSEvent) -> None:
        connections = self._connections.get(event.scan_id, set())
        if not connections:
            return
        message = event.model_dump_json()
        dead: set[WebSocket] = set()
        for ws in connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._connections[event.scan_id].discard(ws)


manager = ConnectionManager()

# Registry of active orchestrators (for stop/pause/resume)
active_orchestrators: Dict[str, ScanOrchestrator] = {}


# ─────────────────────────────────────────────────────────
#  App lifecycle
# ─────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting Tonix Agent (model=%s)", settings.OLLAMA_MODEL)
    await init_db()
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    yield
    log.info("Shutting down Tonix Agent")
    await close_db()


app = FastAPI(
    title="Tonix Agent API",
    description="Local AI-powered penetration testing agent",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ── Rate limit error handler ──────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Security middleware ───────────────────────────────────
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "::1"],
)

# ── CORS — locked to known origins only ──────────────────
_ALLOWED_ORIGINS = [
    f"http://localhost:{settings.FRONTEND_PORT}",
    f"http://127.0.0.1:{settings.FRONTEND_PORT}",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["Content-Disposition"],
)


# ─────────────────────────────────────────────────────────
#  Health
# ─────────────────────────────────────────────────────────

@app.get("/api/health", tags=["System"])
async def health_check():
    """Returns system health: database status + Ollama availability."""
    ollama_ok = await check_ollama_health()
    db_ok     = await check_db_health()
    return {
        "status":       "ok" if db_ok else "degraded",
        "database":     "connected" if db_ok else "error",
        "ollama":       "connected" if ollama_ok else "unavailable",
        "ollama_model": settings.OLLAMA_MODEL,
        "reports_dir":  str(settings.REPORTS_DIR),
    }


# ─────────────────────────────────────────────────────────
#  Analysis tools (JWT) — on-demand, stateless (no scan_id, no DB)
# ─────────────────────────────────────────────────────────

@app.post("/api/tools/jwt", tags=["Tools"])
async def tools_jwt(body: JwtAnalyzeRequest):
    """Decode a JWT and replay forged tokens (alg=none, swap, empty/altered sig)."""
    try:
        return await analyze_jwt(body.token, body.target_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/tools/attach", tags=["Tools"])
async def tools_attach(body: AttachToReportRequest):
    """
    Attach a manual JWT result to an existing scan. Findings are saved to the
    scan; the report picks them up next time the user downloads it. JWT produces
    one finding per check (each its own test case).
    Re-attaching the same tool replaces its previous entries for that scan.
    """
    _validate_scan_id(body.scan_id)
    scan = await get_scan_by_id(body.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        new_findings = build_findings(body.tool, body.scan_id, body.result)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Replace any prior attachment of the same test case(s) for this scan.
    for module in {f.module for f in new_findings}:
        await delete_findings_by_scan_and_module(body.scan_id, module)
    for f in new_findings:
        await save_finding(f.to_db_dict())

    # Refresh the scan's stored counts so dashboards reflect the new finding.
    findings = await get_findings_by_scan(body.scan_id)
    deduped  = await deduplicate_findings(findings)
    await update_scan_counts(body.scan_id, count_by_severity(deduped))
    log.info("Attached %s result to scan %s", body.tool, body.scan_id[:8])
    return {"message": "Result added to the scan report.", "scan_id": body.scan_id}


# ─────────────────────────────────────────────────────────
#  Scan control
# ─────────────────────────────────────────────────────────

@app.post("/api/scan/start", response_model=ScanResponse, tags=["Scan"])
@limiter.limit(f"{settings.SCAN_RATE_LIMIT_PER_MINUTE}/minute")
async def start_scan(
    request: Request,
    body: ScanRequest,
    background_tasks: BackgroundTasks,
):
    """
    Start a new scan.
    Rate limited to SCAN_RATE_LIMIT_PER_MINUTE per IP per minute.
    The scan runs in the background — progress is streamed over WebSocket.
    """
    scan_id = str(uuid.uuid4())
    log.info("Scan requested: %s → %s", scan_id[:8], body.target_url)

    # Create orchestrator eagerly so stop/pause/resume can find it immediately,
    # even before the background task has had a chance to run.
    orchestrator = ScanOrchestrator(
        scan_id=scan_id,
        target_url=body.target_url,
        broadcast=manager.broadcast,
        known_account_email=body.known_account_email,
    )
    active_orchestrators[scan_id] = orchestrator

    async def run_scan() -> None:
        try:
            await orchestrator.run()
        except Exception as exc:
            log.error("Unhandled error in background scan %s: %s", scan_id[:8], exc)
        finally:
            active_orchestrators.pop(scan_id, None)

    background_tasks.add_task(run_scan)

    return ScanResponse(
        scan_id=scan_id,
        target_url=body.target_url,
        status=ScanStatus.RUNNING,
        message=f"Scan started. Connect to /ws/{scan_id} for live updates.",
    )


@app.post("/api/scan/{scan_id}/stop", tags=["Scan"])
async def stop_scan_endpoint(scan_id: str):
    """Stop a running scan."""
    _validate_scan_id(scan_id)
    orchestrator = active_orchestrators.get(scan_id)
    if not orchestrator:
        raise HTTPException(status_code=404, detail="No active scan with that ID")
    orchestrator.cancel()
    log.info("Stop requested: %s", scan_id[:8])
    return {"message": "Scan stop requested"}


@app.post("/api/scan/{scan_id}/pause", tags=["Scan"])
async def pause_scan_endpoint(scan_id: str):
    """Pause a running scan between modules."""
    _validate_scan_id(scan_id)
    orchestrator = active_orchestrators.get(scan_id)
    if not orchestrator:
        raise HTTPException(status_code=404, detail="No active scan with that ID")
    orchestrator.pause()
    return {"message": "Scan paused"}


@app.post("/api/scan/{scan_id}/resume", tags=["Scan"])
async def resume_scan_endpoint(scan_id: str):
    """Resume a paused scan."""
    _validate_scan_id(scan_id)
    orchestrator = active_orchestrators.get(scan_id)
    if not orchestrator:
        raise HTTPException(status_code=404, detail="No active scan with that ID")
    orchestrator.resume()
    return {"message": "Scan resumed"}


@app.delete("/api/scan/{scan_id}", tags=["Scan"])
async def delete_scan(scan_id: str):
    """Delete a scan and all its findings from the database."""
    _validate_scan_id(scan_id)
    # Cannot delete a running scan
    if scan_id in active_orchestrators:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete a scan that is currently running. Stop it first."
        )
    scan = await get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await delete_scan_by_id(scan_id)
    log.info("Scan deleted: %s", scan_id[:8])
    return {"message": "Scan deleted"}


# ─────────────────────────────────────────────────────────
#  Scan data
# ─────────────────────────────────────────────────────────

@app.get("/api/scan/history", tags=["Scan"])
async def scan_history():
    """Return all past scans, most recent first."""
    scans = await get_all_scans()
    return {"scans": scans}


@app.get("/api/scan/{scan_id}", tags=["Scan"])
async def get_scan(scan_id: str):
    """Return a scan record with all its findings."""
    _validate_scan_id(scan_id)
    scan = await get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = await get_findings_by_scan(scan_id)
    return {"scan": scan, "findings": findings}


@app.get("/api/scan/{scan_id}/findings", tags=["Scan"])
async def get_findings(scan_id: str):
    """Return only the findings for a scan."""
    _validate_scan_id(scan_id)
    findings = await get_findings_by_scan(scan_id)
    return {"findings": findings}


_REPORT_MEDIA = {
    "pdf":  "application/pdf",
    "html": "text/html",
}


@app.get("/api/report/{scan_id}", tags=["Reports"])
async def download_report(scan_id: str, format: str = "pdf"):
    """
    Build the report on demand (from the scan's stored findings) and stream it
    as a download. Nothing is persisted server-side: the file is generated into
    a temp dir and deleted once the response has been sent.
    """
    _validate_scan_id(scan_id)
    fmt = (format or "pdf").lower()
    if fmt not in _REPORT_MEDIA:
        raise HTTPException(status_code=400, detail="Invalid format (use pdf or html)")

    scan = await get_scan_by_id(scan_id)
    if not scan or scan.get("status") != "completed":
        raise HTTPException(status_code=404, detail="Report not available for this scan")

    tmp_dir, report_path = await build_report(scan_id, fmt)
    return FileResponse(
        path=report_path,
        media_type=_REPORT_MEDIA[fmt],
        filename=Path(report_path).name,
        background=BackgroundTask(shutil.rmtree, tmp_dir, ignore_errors=True),
    )


# ─────────────────────────────────────────────────────────
#  WebSocket
# ─────────────────────────────────────────────────────────

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """Real-time event stream for a scan."""
    if not _UUID_RE.match(scan_id):
        await websocket.close(code=4000)
        return
    await manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()   # keep-alive; we only push, not pull
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
        log.debug("WS disconnected: scan=%s", scan_id[:8])


# ─────────────────────────────────────────────────────────
#  Serve React frontend (production build)
# ─────────────────────────────────────────────────────────

FRONTEND_BUILD = Path(__file__).parent.parent / "frontend" / "dist"

if FRONTEND_BUILD.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=FRONTEND_BUILD / "assets"),
        name="assets",
    )

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_react(full_path: str):
        index = FRONTEND_BUILD / "index.html"
        if index.exists():
            return FileResponse(index)
        return HTMLResponse("<h1>Frontend not built yet. Run: cd frontend && npm run build</h1>")