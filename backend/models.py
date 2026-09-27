"""
models.py
─────────
All shared Pydantic models used across the API, orchestrator,
scan modules, and WebSocket events.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Any
from pydantic import BaseModel, field_validator
import uuid


# ─────────────────────────────────────────────────────────
#  Enums
# ─────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    PAUSED    = "paused"
    COMPLETED = "completed"
    FAILED    = "failed"
    STOPPED   = "stopped"


class WSEventType(str, Enum):
    SCAN_STARTED        = "scan_started"
    CRAWL_STARTED       = "crawl_started"       # browser crawl begins
    CRAWL_PROGRESS      = "crawl_progress"      # per-page crawl progress
    CRAWL_COMPLETED     = "crawl_completed"     # browser crawl finished
    CRAWL_FAILED        = "crawl_failed"        # browser crawl error
    MODULE_STARTED      = "module_started"
    MODULE_PROGRESS     = "module_progress"     # NEW — per-module sub-progress
    MODULE_COMPLETED    = "module_completed"
    MODULE_SKIPPED      = "module_skipped"
    FINDING_DISCOVERED  = "finding_discovered"
    CRITICAL_FINDING    = "critical_finding"
    SCAN_COMPLETED      = "scan_completed"
    SCAN_FAILED         = "scan_failed"
    SCAN_STOPPED        = "scan_stopped"
    SCAN_PAUSED         = "scan_paused"
    SCAN_RESUMED        = "scan_resumed"
    LOG                 = "log"


# ─────────────────────────────────────────────────────────
#  CrawlResult — produced by PlaywrightCrawler, stored on
#  ScopeEnforcer, consumed by the crawl-aware modules
# ─────────────────────────────────────────────────────────

@dataclass
class CrawlResult:
    """
    Holds every URL discovered by Katana, pre-classified into
    typed buckets so each module can pick exactly what it needs.

    Buckets:
      all_urls      — every in-scope URL discovered (used by most modules)
      endpoints     — path-only strings e.g. ["/api/v1/users", "/login"]
      api_endpoints — full URLs whose path starts with /api (used by http_bypass)
      forms         — full URLs of pages that contain HTML forms
      js_files      — full URLs of .js resources
    """
    all_urls:      list[str] = field(default_factory=list)
    endpoints:     list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    forms:         list[str] = field(default_factory=list)
    js_files:      list[str] = field(default_factory=list)
    crawl_duration: float    = 0.0   # seconds Katana took

    @property
    def url_count(self) -> int:
        return len(self.all_urls)

    @property
    def api_count(self) -> int:
        return len(self.api_endpoints)

    @property
    def form_count(self) -> int:
        return len(self.forms)

    @property
    def js_count(self) -> int:
        return len(self.js_files)

    @property
    def verified_urls(self) -> list[str]:
        """The single deduplicated final output: pages + api + js, unique."""
        return list(dict.fromkeys(self.all_urls + self.api_endpoints + self.js_files))

    def summary(self) -> dict:
        """Serialisable summary for WS events and reports."""
        return {
            "url_count":      self.url_count,
            "api_count":      self.api_count,
            "form_count":     self.form_count,
            "js_count":       self.js_count,
            "crawl_duration": round(self.crawl_duration, 1),
            "all_urls":       self.all_urls,
            "api_endpoints":  self.api_endpoints,
            "forms":          self.forms,
            "js_files":       self.js_files,
            "verified_urls":  self.verified_urls,
        }


# ─────────────────────────────────────────────────────────
#  Finding
# ─────────────────────────────────────────────────────────

class Finding(BaseModel):
    id:             str = ""
    scan_id:        str = ""
    module:         str
    title:          str
    severity:       Severity
    description:    str = ""
    evidence:       str = ""
    affected_urls:  List[str] = []
    request_data:   str = ""
    response_data:  str = ""
    remediation:    str = ""
    # Optional per-finding CVSS. When a module sets these (e.g. impact varies by
    # what the scan actually reveals), the report shows them instead of the
    # catalog's static score. None = fall back to the catalog value.
    cvss_score:     Optional[float] = None
    cvss_vector:    str = ""
    is_critical:    bool = False

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = str(uuid.uuid4())
        # Auto-flag critical / high as requiring immediate notification
        if self.severity in (Severity.CRITICAL, Severity.HIGH):
            self.is_critical = True

    def to_db_dict(self) -> dict:
        return self.model_dump()


# ─────────────────────────────────────────────────────────
#  Scan request / response
# ─────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target_url: str
    # Optional: one email/username KNOWN to exist on the target. Enables the
    # username_enum module's reliable login-form differential check. Safe to
    # omit — the module falls back to its message-based detection without it.
    known_account_email: Optional[str] = None

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        return v


class ScanResponse(BaseModel):
    scan_id:    str
    target_url: str
    status:     ScanStatus
    message:    str


# ─────────────────────────────────────────────────────────
#  Analysis tools (JWT) — on-demand, not part of a scan
# ─────────────────────────────────────────────────────────

class JwtAnalyzeRequest(BaseModel):
    token: str
    target_url: Optional[str] = None   # optional endpoint to replay forged tokens against


class AttachToReportRequest(BaseModel):
    scan_id: str
    tool: str            # "jwt"
    result: dict         # the tool's own result payload (from /api/tools/jwt)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        if v != "jwt":
            raise ValueError("tool must be 'jwt'")
        return v


# ─────────────────────────────────────────────────────────
#  WebSocket event envelope
# ─────────────────────────────────────────────────────────

class WSEvent(BaseModel):
    event:   WSEventType
    scan_id: str
    data:    dict = {}

    @classmethod
    def crawl_started(cls, scan_id: str, target_url: str) -> "WSEvent":
        return cls(
            event=WSEventType.CRAWL_STARTED,
            scan_id=scan_id,
            data={"target_url": target_url, "message": "Browser crawl started..."},
        )

    @classmethod
    def crawl_progress(cls, scan_id: str, pages_visited: int,
                       pages_total: int, urls_found: int) -> "WSEvent":
        return cls(
            event=WSEventType.CRAWL_PROGRESS,
            scan_id=scan_id,
            data={
                "pages_visited": pages_visited,
                "pages_total":   pages_total,
                "urls_found":    urls_found,
            },
        )

    @classmethod
    def crawl_completed(cls, scan_id: str, crawl_result: CrawlResult) -> "WSEvent":
        return cls(
            event=WSEventType.CRAWL_COMPLETED,
            scan_id=scan_id,
            data={
                "message": f"Crawl complete — {crawl_result.url_count} URLs discovered",
                **crawl_result.summary(),
            },
        )

    @classmethod
    def crawl_failed(cls, scan_id: str, reason: str) -> "WSEvent":
        return cls(
            event=WSEventType.CRAWL_FAILED,
            scan_id=scan_id,
            data={"reason": reason},
        )

    @classmethod
    def finding_discovered(cls, scan_id: str, finding: Finding) -> "WSEvent":
        event_type = (
            WSEventType.CRITICAL_FINDING
            if finding.is_critical
            else WSEventType.FINDING_DISCOVERED
        )
        return cls(
            event=event_type,
            scan_id=scan_id,
            data=finding.model_dump(),
        )

    @classmethod
    def scan_completed(cls, scan_id: str, summary: dict) -> "WSEvent":
        return cls(
            event=WSEventType.SCAN_COMPLETED,
            scan_id=scan_id,
            data=summary,
        )

    @classmethod
    def scan_failed(cls, scan_id: str, reason: str) -> "WSEvent":
        return cls(
            event=WSEventType.SCAN_FAILED,
            scan_id=scan_id,
            data={"reason": reason},
        )

    @classmethod
    def scan_stopped(cls, scan_id: str, counts: dict | None = None) -> "WSEvent":
        return cls(
            event=WSEventType.SCAN_STOPPED,
            scan_id=scan_id,
            data={"reason": "Stopped by user", "counts": counts or {}},
        )

    @classmethod
    def scan_paused(cls, scan_id: str) -> "WSEvent":
        return cls(
            event=WSEventType.SCAN_PAUSED,
            scan_id=scan_id,
            data={},
        )

    @classmethod
    def scan_resumed(cls, scan_id: str) -> "WSEvent":
        return cls(
            event=WSEventType.SCAN_RESUMED,
            scan_id=scan_id,
            data={},
        )
