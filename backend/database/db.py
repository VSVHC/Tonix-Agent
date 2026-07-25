"""
database/db.py
──────────────
SQLite database layer using aiosqlite (async).

Key improvements over v1:
  - Single persistent connection opened at startup (no open/close per call)
  - WAL journal mode for better concurrent read performance
  - All queries use the shared connection via a module-level reference
  - Properly typed function signatures throughout
"""

import json
import aiosqlite
from datetime import datetime, timezone
from typing import Optional

from backend.config import settings
from backend.logger import get_logger

log = get_logger(__name__)

# ── Persistent connection — set by init_db(), used by all helpers ──
_db: Optional[aiosqlite.Connection] = None


# ─────────────────────────────────────────────────────────
#  Schema
# ─────────────────────────────────────────────────────────

CREATE_SCANS_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    target_url      TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    status          TEXT NOT NULL DEFAULT 'running',
    report_path     TEXT,
    total_findings  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    info_count      INTEGER DEFAULT 0
);
"""

CREATE_FINDINGS_TABLE = """
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    module          TEXT NOT NULL,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL,
    description     TEXT,
    evidence        TEXT,
    affected_urls   TEXT,
    request_data    TEXT,
    response_data   TEXT,
    remediation     TEXT,
    is_critical     INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);",
    "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);",
    "CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);",
]


# ─────────────────────────────────────────────────────────
#  Connection management
# ─────────────────────────────────────────────────────────

async def init_db() -> None:
    """
    Open the persistent database connection and initialise schema.
    Call once at application startup.
    """
    global _db
    log.info("Initialising database at %s", settings.DATABASE_PATH)
    _db = await aiosqlite.connect(settings.DATABASE_PATH)
    _db.row_factory = aiosqlite.Row

    # WAL mode: readers don't block writers and vice-versa
    await _db.execute("PRAGMA journal_mode=WAL;")
    await _db.execute("PRAGMA foreign_keys=ON;")
    await _db.execute("PRAGMA synchronous=NORMAL;")

    await _db.execute(CREATE_SCANS_TABLE)
    await _db.execute(CREATE_FINDINGS_TABLE)
    for idx in CREATE_INDEXES:
        await _db.execute(idx)
    await _db.commit()
    log.info("Database ready")


async def close_db() -> None:
    """Close the persistent connection. Call on application shutdown."""
    global _db
    if _db:
        await _db.close()
        _db = None
        log.info("Database connection closed")


def _conn() -> aiosqlite.Connection:
    """Return the active connection, raising clearly if not initialised."""
    if _db is None:
        raise RuntimeError("Database not initialised — call init_db() first")
    return _db


async def check_db_health() -> bool:
    """Return True if the database connection is open and answering queries."""
    if _db is None:
        return False
    try:
        async with _db.execute("SELECT 1") as cursor:
            await cursor.fetchone()
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────
#  Scan helpers
# ─────────────────────────────────────────────────────────

async def create_scan(scan_id: str, target_url: str) -> dict:
    """Insert a new scan record."""
    started_at = datetime.now(timezone.utc).isoformat()
    await _conn().execute(
        "INSERT INTO scans (id, target_url, started_at, status) VALUES (?, ?, ?, 'running')",
        (scan_id, target_url, started_at),
    )
    await _conn().commit()
    log.debug("Scan created: %s → %s", scan_id, target_url)
    return {"id": scan_id, "target_url": target_url, "started_at": started_at, "status": "running"}


async def complete_scan(scan_id: str, counts: dict) -> None:
    """Mark a scan as completed and store final counts."""
    completed_at = datetime.now(timezone.utc).isoformat()
    await _conn().execute(
        """UPDATE scans SET
            status         = 'completed',
            completed_at   = ?,
            total_findings = ?,
            critical_count = ?,
            high_count     = ?,
            medium_count   = ?,
            low_count      = ?,
            info_count     = ?
           WHERE id = ?""",
        (
            completed_at,
            counts.get("total", 0), counts.get("critical", 0),
            counts.get("high", 0),  counts.get("medium", 0),
            counts.get("low", 0),   counts.get("info", 0),
            scan_id,
        ),
    )
    await _conn().commit()
    log.debug("Scan completed: %s", scan_id)


async def update_scan_counts(scan_id: str, counts: dict) -> None:
    """
    Refresh a scan's finding counts without changing its status.
    Used when a manual JWT result is attached to a scan.
    """
    await _conn().execute(
        """UPDATE scans SET
            total_findings = ?,
            critical_count = ?,
            high_count     = ?,
            medium_count   = ?,
            low_count      = ?,
            info_count     = ?
           WHERE id = ?""",
        (
            counts.get("total", 0), counts.get("critical", 0),
            counts.get("high", 0),  counts.get("medium", 0),
            counts.get("low", 0),   counts.get("info", 0),
            scan_id,
        ),
    )
    await _conn().commit()


async def fail_scan(scan_id: str, reason: str) -> None:
    """Mark a scan as failed."""
    await _conn().execute(
        "UPDATE scans SET status = 'failed', completed_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), scan_id),
    )
    await _conn().commit()
    log.warning("Scan failed: %s — %s", scan_id, reason[:200])


async def stop_scan(scan_id: str) -> None:
    """Mark a scan as stopped and snapshot current finding counts."""
    completed_at = datetime.now(timezone.utc).isoformat()
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    async with _conn().execute(
        "SELECT severity, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY severity",
        (scan_id,),
    ) as cursor:
        async for row in cursor:
            sev = (row[0] or "info").lower()
            if sev in counts:
                counts[sev] = row[1]
    total = sum(counts.values())

    await _conn().execute(
        """UPDATE scans SET
            status         = 'stopped',
            completed_at   = ?,
            total_findings = ?,
            critical_count = ?,
            high_count     = ?,
            medium_count   = ?,
            low_count      = ?,
            info_count     = ?
           WHERE id = ?""",
        (
            completed_at, total,
            counts["critical"], counts["high"],
            counts["medium"],   counts["low"],
            counts["info"],     scan_id,
        ),
    )
    await _conn().commit()


async def pause_scan_db(scan_id: str) -> None:
    await _conn().execute("UPDATE scans SET status = 'paused' WHERE id = ?", (scan_id,))
    await _conn().commit()


async def resume_scan_db(scan_id: str) -> None:
    await _conn().execute("UPDATE scans SET status = 'running' WHERE id = ?", (scan_id,))
    await _conn().commit()


async def get_all_scans() -> list[dict]:
    """Return all scans ordered by most recent first."""
    async with _conn().execute("SELECT * FROM scans ORDER BY started_at DESC") as cursor:
        rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def get_scan_by_id(scan_id: str) -> Optional[dict]:
    """Return a single scan by ID."""
    async with _conn().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)) as cursor:
        row = await cursor.fetchone()
    return dict(row) if row else None


# ─────────────────────────────────────────────────────────
#  Finding helpers
# ─────────────────────────────────────────────────────────

async def save_finding(finding: dict) -> None:
    """Insert a finding into the database."""
    await _conn().execute(
        """INSERT INTO findings (
            id, scan_id, module, title, severity,
            description, evidence, affected_urls,
            request_data, response_data, remediation,
            is_critical, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            finding["id"],
            finding["scan_id"],
            finding["module"],
            finding["title"],
            finding["severity"],
            finding.get("description", ""),
            finding.get("evidence", ""),
            json.dumps(finding.get("affected_urls", [])),
            finding.get("request_data", ""),
            finding.get("response_data", ""),
            finding.get("remediation", ""),
            1 if finding.get("is_critical") else 0,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    await _conn().commit()


async def get_findings_by_scan(scan_id: str) -> list[dict]:
    """Return all findings for a given scan, ordered by severity."""
    async with _conn().execute(
        """SELECT * FROM findings WHERE scan_id = ?
           ORDER BY CASE severity
             WHEN 'critical' THEN 0 WHEN 'high' THEN 1
             WHEN 'medium'   THEN 2 WHEN 'low'  THEN 3
             ELSE 4 END""",
        (scan_id,),
    ) as cursor:
        rows = await cursor.fetchall()

    results = []
    for row in rows:
        r = dict(row)
        try:
            r["affected_urls"] = json.loads(r.get("affected_urls") or "[]")
        except (json.JSONDecodeError, TypeError):
            r["affected_urls"] = []
        results.append(r)
    return results


async def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """
    Merge findings with the same title + module.
    All affected URLs are combined into one entry.
    """
    seen: dict[str, dict] = {}
    for f in findings:
        key = f"{f['module']}::{f['title']}"
        if key not in seen:
            seen[key] = f.copy()
            seen[key]["affected_urls"] = list(f.get("affected_urls") or [])
        else:
            existing = seen[key]["affected_urls"]
            for url in (f.get("affected_urls") or []):
                if url not in existing:
                    existing.append(url)
    return list(seen.values())


async def delete_findings_by_scan_and_module(scan_id: str, module: str) -> None:
    """
    Remove all findings for one module of a scan.
    Used before a paused module is re-run on resume, so partial results saved
    before the interruption don't become duplicate rows.
    """
    await _conn().execute(
        "DELETE FROM findings WHERE scan_id = ? AND module = ?",
        (scan_id, module),
    )
    await _conn().commit()


async def delete_scan_by_id(scan_id: str) -> None:
    """Delete a scan and all its findings from the database."""
    await _conn().execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    await _conn().execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    await _conn().commit()
    log.debug("Scan deleted: %s", scan_id)
