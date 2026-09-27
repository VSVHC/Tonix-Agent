"""
orchestrator.py
───────────────
The brain of the Tonix Agent — split into focused classes.

Classes:
  ScanRunner      — executes modules one-by-one, handles pause/cancel
  ScanFinaliser   — deduplicates findings, generates report, sends Slack
  ScanOrchestrator — public interface: wires Runner + Finaliser together

Crawler integration:
  Before the module loop starts, PlaywrightCrawler runs against the target
  and populates scope.crawl_result with all discovered URLs.
  The 8 crawl-aware modules read from scope.crawl_result instead of
  testing only the root URL.
  If the browser crawl fails (Playwright/Chromium missing), the scan is
  stopped immediately with a clear error — there is no Katana fallback.
"""

import asyncio
import httpx
import traceback
from datetime import datetime, timezone
from typing import Callable, Awaitable, Type

from backend.config import settings
from backend.scope import ScopeEnforcer
from backend.models import Finding, Severity, WSEvent, WSEventType, CrawlResult
from backend.database.db import (
    create_scan, complete_scan, fail_scan, stop_scan,
    pause_scan_db, resume_scan_db,
    save_finding, deduplicate_findings, save_scan_analysis,
    delete_findings_by_scan_and_module,
)
from backend.llm import enrich_findings_concurrent, summarize_scan
from backend.notifications.slack import notify_critical_finding, notify_scan_complete
from backend.reports.catalog import BY_NAME
from backend.modules.base_module import BaseModule
from backend.modules.playwright_crawler import PlaywrightCrawler, PlaywrightCrawlError
from backend.logger import get_logger

# ── Import all scan modules ──────────────────────────────
from backend.modules.autocomplete      import AutocompleteModule
from backend.modules.headers           import HeadersModule
from backend.modules.trace             import TraceModule
from backend.modules.clickjacking      import ClickjackingModule
from backend.modules.host_header       import HostHeaderModule
from backend.modules.http_bypass       import HttpBypassModule
from backend.modules.unencrypted_communication import UnencryptedCommunicationModule
from backend.modules.error_exceptions  import ErrorExceptionsModule
from backend.modules.git_enum          import GitEnumModule
from backend.modules.web_server        import WebServerModule
from backend.modules.req_splitting     import ReqSplittingModule
from backend.modules.res_splitting     import ResSplittingModule
from backend.modules.js_enum           import JsEnumModule
from backend.modules.directory_listing import DirectoryListingModule
from backend.modules.username_enum     import UsernameEnumModule
from backend.modules.sitemap           import SitemapModule
from backend.modules.robots            import RobotsModule
from backend.modules.captcha           import CaptchaModule
from backend.modules.crossdomain       import CrossDomainModule
from backend.modules.cors              import CorsModule

# Type alias for the WebSocket event broadcaster
EventBroadcaster = Callable[[WSEvent], Awaitable[None]]

# ── Ordered list of all modules to run ──────────────────
ALL_MODULES: list[Type[BaseModule]] = [
    CrossDomainModule,
    SitemapModule,
    RobotsModule,
    GitEnumModule,
    HeadersModule,
    WebServerModule,
    ClickjackingModule,
    ErrorExceptionsModule,
    HostHeaderModule,
    UnencryptedCommunicationModule,
    HttpBypassModule,
    TraceModule,
    AutocompleteModule,
    ReqSplittingModule,
    ResSplittingModule,
    DirectoryListingModule,
    JsEnumModule,
    UsernameEnumModule,
    CaptchaModule,
    CorsModule,
]

# ── Crawl-aware modules — these iterate crawl_result URLs ──
# The other 12 modules remain unchanged and test root URL only.
PLAYWRIGHT_MODULES: set[str] = {
    "clickjacking",
    "trace",
    "host_header",
    "http_bypass",
    "error_exceptions",
    "req_splitting",
    "res_splitting",
    "cors",
}

TOTAL_MODULES = len(ALL_MODULES)


# ─────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────

def _is_benign(finding) -> bool:
    """A '…Not Vulnerable' marker carrying PoC for a passed test case — not a vuln."""
    title = finding.title if hasattr(finding, "title") else finding.get("title", "")
    return "not vulnerable" in (title or "").lower()


def _count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if _is_benign(f):
            continue   # benign "Not Vulnerable" markers never count as findings
        sev = (f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
    counts["total"] = sum(counts.values())
    return counts


# ─────────────────────────────────────────────────────────
#  Request/response capture — records the real bytes a module
#  exchanges so a "Not Vulnerable" test case can still show the
#  same Evidence / Request / Response as a vulnerability.
# ─────────────────────────────────────────────────────────

def _format_request(req: httpx.Request) -> str:
    try:
        path = req.url.raw_path.decode("ascii", "replace")
    except Exception:
        path = req.url.path or "/"
    lines = [f"{req.method} {path or '/'} HTTP/1.1", f"Host: {req.url.host}"]
    for k, v in req.headers.items():
        if k.lower() != "host":
            lines.append(f"{k}: {v}")
    text = "\n".join(lines)
    try:
        body = req.content or b""
    except Exception:
        body = b""
    if body:
        text += "\n\n" + body[:1000].decode("utf-8", "replace")
    return text


def _format_response(resp: httpx.Response, body: str) -> str:
    lines = [f"HTTP {resp.status_code} {resp.reason_phrase}"]
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    text = "\n".join(lines)
    if body:
        text += "\n\n" + body
    return text


class _Capture:
    """Records request/response pairs during a single module's run."""

    def __init__(self, max_records: int = 6, body_limit: int = 3000) -> None:
        self.records: list[dict] = []
        self.enabled = False
        self.max_records = max_records
        self.body_limit = body_limit

    def reset(self) -> None:
        self.records = []

    async def hook(self, response: httpx.Response) -> None:
        if not self.enabled or len(self.records) >= self.max_records:
            return
        try:
            if not response.is_stream_consumed:
                await response.aread()
            body = response.text[: self.body_limit]
        except Exception:
            body = ""
        try:
            self.records.append({
                "url":      str(response.request.url),
                "status":   response.status_code,
                "request":  _format_request(response.request),
                "response": _format_response(response, body),
            })
        except Exception:
            pass


def _build_client() -> httpx.AsyncClient:
    """Create the shared HTTP client for a scan."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(settings.REQUEST_TIMEOUT),
        headers=settings.REQUEST_HEADERS,
        follow_redirects=True,
        verify=False,   # pentest tool — we want to hit misconfigured TLS too
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )


# ─────────────────────────────────────────────────────────
#  Shared WS-emit helper — used by every class below. Each has
#  `self.broadcast` and `self._log`, so one implementation covers all.
# ─────────────────────────────────────────────────────────

class _EmitsEvents:
    async def _emit(self, event: WSEvent) -> None:
        try:
            await self.broadcast(event)
        except Exception as exc:
            self._log.debug("WS broadcast failed: %s", exc)


# ─────────────────────────────────────────────────────────
#  ScanRunner — executes modules, handles pause / cancel
# ─────────────────────────────────────────────────────────

class ScanRunner(_EmitsEvents):
    """
    Runs all modules in order on a single shared HTTP client.
    Emits WS events for every module start/complete/finding.
    Handles pause, resume, and cancel — including mid-module.

    Cancel: asyncio.Task.cancel() is called on the running module task,
            so it raises CancelledError at the next await point inside the
            module — no waiting for the module to finish.
    Pause:  the running module task is cancelled, and the module is
            replayed from scratch after resume. Simpler and safer than
            trying to suspend arbitrary async code mid-flight.
    """

    def __init__(
        self,
        scan_id: str,
        scope: ScopeEnforcer,
        client: httpx.AsyncClient,
        broadcast: EventBroadcaster,
    ) -> None:
        self.scan_id    = scan_id
        self.scope      = scope
        self.client     = client
        self.broadcast  = broadcast
        self._log       = get_logger(f"runner.{scan_id[:8]}")
        self._cancelled = False
        self._paused    = False
        self._current_task: asyncio.Task | None = None
        self.all_findings: list[Finding] = []
        # Capture the real HTTP bytes each module exchanges (for non-vuln PoC).
        self._capture = _Capture()
        client.event_hooks = {"request": [], "response": [self._capture.hook]}
        # Per-module execution status for the report:
        #   'not_applicable' — the module raised (couldn't complete)
        #   'ran'            — the module completed (vuln/not-vuln derived from findings)
        self.module_status: dict[str, str] = {}

    # ── Control signals (called from FastAPI route handlers) ─
    def cancel(self) -> None:
        self._cancelled = True
        if self._current_task and not self._current_task.done():
            self._current_task.cancel()

    def pause(self) -> None:
        self._paused = True
        if self._current_task and not self._current_task.done():
            self._current_task.cancel()   # interrupt the running module immediately

    def resume(self) -> None:
        self._paused = False              # run_all() loop will re-run the paused module

    # ── Main loop ─────────────────────────────────────────

    async def run_all(self) -> list[Finding]:
        """
        Run every module in ALL_MODULES order.
        Supports instant cancel and instant pause (mid-module).
        """
        idx = 0
        while idx < len(ALL_MODULES):
            ModuleClass = ALL_MODULES[idx]

            # ── Cancel check ──────────────────────────────
            if self._cancelled:
                self._log.warning("Scan cancelled before module %s", ModuleClass.name)
                return self.all_findings

            # ── Pause: wait here until resumed or cancelled ──
            if self._paused:
                await pause_scan_db(self.scan_id)
                await self._emit(WSEvent.scan_paused(self.scan_id))
                self._log.info("Scan paused before %s", ModuleClass.name)
                while self._paused:
                    await asyncio.sleep(0.25)
                    if self._cancelled:
                        return self.all_findings
                await resume_scan_db(self.scan_id)
                await self._emit(WSEvent.scan_resumed(self.scan_id))
                self._log.info("Scan resumed at %s", ModuleClass.name)
                # don't advance idx — re-run the module that was interrupted

            # ── Run module as a cancellable task ──────────
            completed = await self._run_one_cancellable(ModuleClass, index=idx + 1)

            if completed:
                idx += 1   # advance only on successful completion
            elif self._cancelled:
                return self.all_findings
            # if paused mid-module: loop back, hit the pause block above, wait

        return self.all_findings

    async def _run_one_cancellable(
        self, ModuleClass: type[BaseModule], index: int
    ) -> bool:
        """
        Run a single module wrapped in an asyncio.Task so it can be
        cancelled instantly via cancel() or pause().

        Returns True  -> module completed normally (advance to next)
                False -> module was cancelled/paused (caller decides what to do)
        """
        task = asyncio.ensure_future(self._run_one(ModuleClass, index=index))
        self._current_task = task
        try:
            await task
            return True
        except asyncio.CancelledError:
            if self._cancelled:
                self._log.info("[%s] Module cancelled (stop requested)", ModuleClass.name)
            else:
                self._log.info("[%s] Module interrupted (pause requested)", ModuleClass.name)
            return False
        finally:
            self._current_task = None

    async def _emit_progress(self, module_name: str, done: int, total: int) -> None:
        """Broadcast a module's own completion fraction (0–100)."""
        pct = round(done / total * 100) if total else 0
        await self._emit(WSEvent(
            event=WSEventType.MODULE_PROGRESS,
            scan_id=self.scan_id,
            data={"module": module_name, "percent": pct, "done": done, "total": total},
        ))

    async def _run_one(self, ModuleClass: Type[BaseModule], index: int) -> None:
        module_name = ModuleClass.name
        started_at  = datetime.now(timezone.utc)
        pct         = round((index - 1) / TOTAL_MODULES * 100)

        # Idempotency: a paused module is re-run from scratch after resume.
        # Drop anything this module may have partially saved before the
        # interruption — in memory and in the DB — so we never duplicate rows.
        self.all_findings = [f for f in self.all_findings if f.module != module_name]
        await delete_findings_by_scan_and_module(self.scan_id, module_name)

        await self._emit(WSEvent(
            event=WSEventType.MODULE_STARTED,
            scan_id=self.scan_id,
            data={
                "module":            module_name,
                "index":             index,
                "total":             TOTAL_MODULES,
                "percent_complete":  pct,
                "playwright_enabled": module_name in PLAYWRIGHT_MODULES,
            },
        ))
        self._log.info("[%s] Starting (%d/%d)", module_name, index, TOTAL_MODULES)

        self._capture.reset()
        self._capture.enabled = True
        try:
            module = ModuleClass(
                scope=self.scope,
                scan_id=self.scan_id,
                client=self.client,
                progress_cb=self._emit_progress,
            )
            raw_findings: list[Finding] = await module.run()

        except asyncio.CancelledError:
            self._capture.enabled = False
            raise
        except Exception as exc:
            self._capture.enabled = False
            elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
            self._log.error(
                "[%s] ERROR after %.1fs: %s\n%s",
                module_name, elapsed, exc, traceback.format_exc()
            )
            self.module_status[module_name] = "not_applicable"
            await self._emit(WSEvent(
                event=WSEventType.MODULE_COMPLETED,
                scan_id=self.scan_id,
                data={
                    "module":           module_name,
                    "finding_count":    0,
                    "error":            str(exc),
                    "elapsed_seconds":  round(elapsed, 1),
                    "percent_complete": round(index / TOTAL_MODULES * 100),
                },
            ))
            return   # Don't abort — continue with next module

        self._capture.enabled = False

        # Module completed — vuln/not-vuln is derived from findings at report time.
        self.module_status[module_name] = "ran"

        real   = [f for f in raw_findings if not _is_benign(f)]
        benign = [f for f in raw_findings if _is_benign(f)]

        # ── Real vulnerabilities: LLM-enriched, saved, emitted ──
        if real:
            self._log.info("[%s] Enriching %d finding(s) via LLM", module_name, len(real))
            enriched_data = await enrich_findings_concurrent(real)
            for finding, enriched in zip(real, enriched_data):
                # Only description/remediation are LLM-enriched. Severity is
                # authoritative from the module and must NOT be overwritten.
                finding.description = enriched.get("description", finding.description)
                finding.remediation = enriched.get("remediation", finding.remediation)
                finding.is_critical = finding.severity in (Severity.CRITICAL, Severity.HIGH)
                finding.scan_id     = self.scan_id

                await save_finding(finding.to_db_dict())
                self.all_findings.append(finding)
                await self._emit(WSEvent.finding_discovered(self.scan_id, finding))

                if finding.is_critical:
                    self._log.warning("[%s] Critical: %s", module_name, finding.title)
                    await notify_critical_finding(finding, self.scope.target_url)

        # ── Not vulnerable: attach the real captured request/response as PoC so
        #    the report + UI show the same Evidence/Request fields as a vuln. ──
        else:
            poc = self._build_benign_finding(module_name, benign)
            if poc:
                poc.scan_id = self.scan_id
                await save_finding(poc.to_db_dict())
                self.all_findings.append(poc)
                await self._emit(WSEvent.finding_discovered(self.scan_id, poc))

        elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
        self._log.info(
            "[%s] Done in %.1fs — %d finding(s)", module_name, elapsed, len(real)
        )
        await self._emit(WSEvent(
            event=WSEventType.MODULE_COMPLETED,
            scan_id=self.scan_id,
            data={
                "module":            module_name,
                "finding_count":     len(real),
                "elapsed_seconds":   round(elapsed, 1),
                "percent_complete":  round(index / TOTAL_MODULES * 100),
            },
        ))

    def _build_benign_finding(
        self, module_name: str, existing_benign: list[Finding]
    ) -> Finding | None:
        """
        Build (or enrich) the '…Not Vulnerable' marker for a passed test case,
        carrying the real request/response bytes captured during the run so the
        report and UI can show the same Evidence/Request as a vulnerability.
        Returns None when the module made no capturable request and emitted no
        marker of its own (nothing to show).
        """
        tc      = BY_NAME.get(module_name, {})
        records = self._capture.records
        req     = records[0]["request"]  if records else ""
        resp    = records[0]["response"] if records else ""
        urls    = list(dict.fromkeys(r["url"] for r in records))[:15]

        if existing_benign:
            f = existing_benign[0]
            if not f.request_data:  f.request_data  = req
            if not f.response_data: f.response_data = resp
            if not f.evidence:      f.evidence      = self._benign_evidence(records)
            if not f.affected_urls: f.affected_urls = urls
            return f

        if not records:
            return None

        return Finding(
            scan_id=self.scan_id,
            module=module_name,
            title=f"{tc.get('title', module_name)} — Not Vulnerable",
            severity=Severity.INFO,
            description=tc.get("description", ""),
            evidence=self._benign_evidence(records),
            affected_urls=urls,
            request_data=req,
            response_data=resp,
            remediation=tc.get("remediation", ""),
        )

    @staticmethod
    def _benign_evidence(records: list[dict]) -> str:
        if not records:
            return "This test case was checked and the target passed — no issue was found."
        lines = [
            f"This test case was checked and the target passed — no issue was found.",
            f"Requests exchanged during the check ({len(records)}):",
            "",
        ]
        for r in records:
            lines.append(f"• HTTP {r['status']}  {r['url']}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────
#  ScanFinaliser — dedup, report, Slack, DB completion
# ─────────────────────────────────────────────────────────

class ScanFinaliser(_EmitsEvents):
    """
    Everything that happens after all modules finish:
      1. Deduplicate findings
      2. Mark scan complete in DB
      3. Send Slack summary
      4. Emit scan_completed WS event
    (Reports are built on demand at download time, not here.)
    """

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        broadcast: EventBroadcaster,
    ) -> None:
        self.scan_id          = scan_id
        self.target_url       = target_url
        self.broadcast        = broadcast
        self._log             = get_logger(f"finaliser.{scan_id[:8]}")

    async def finalise(
        self,
        findings: list[Finding],
        crawl_result: CrawlResult | None = None,
        status_map: dict[str, str] | None = None,
    ) -> None:
        raw     = [f.to_db_dict() for f in findings]
        deduped = await deduplicate_findings(raw)
        counts  = _count_by_severity(deduped)

        self._log.info(
            "Scan summary — total=%d critical=%d high=%d medium=%d low=%d info=%d",
            counts["total"], counts["critical"], counts["high"],
            counts["medium"], counts["low"], counts["info"],
        )

        # ── LLM: one pass over all real findings → exec summary + attack chains ──
        real = [f for f in findings if not _is_benign(f)]
        analysis = await summarize_scan(real, self.target_url)
        await save_scan_analysis(
            self.scan_id, analysis["summary"], analysis["correlations"]
        )
        if analysis["summary"] or analysis["correlations"]:
            self._log.info(
                "LLM analysis — summary=%d chars, %d chain(s)",
                len(analysis["summary"]), len(analysis["correlations"]),
            )

        # No files written here: PDF/HTML reports are generated on demand at
        # download time from the stored findings (see /api/report endpoint).
        await complete_scan(self.scan_id, counts)

        await notify_scan_complete(
            target_url=self.target_url,
            scan_id=self.scan_id,
            counts=counts,
        )

        await self._emit(WSEvent.scan_completed(
            self.scan_id,
            {
                "counts":          counts,
                "total_modules":   TOTAL_MODULES,
                "ai_summary":      analysis["summary"],
                "ai_correlations": analysis["correlations"],
            },
        ))
        self._log.info("Scan complete ✓")

# ─────────────────────────────────────────────────────────
#  ScanOrchestrator — public interface
# ─────────────────────────────────────────────────────────

class ScanOrchestrator(_EmitsEvents):
    """
    Public entry point. One instance per scan.

    Lifecycle:
      1. Create DB scan record + emit SCAN_STARTED
      2. Run Katana crawl → emit CRAWL_STARTED / CRAWL_COMPLETED
         (if Katana fails → emit CRAWL_FAILED → stop scan)
      3. Run all modules sequentially (see ALL_MODULES for the full list)
         (7 Katana modules iterate crawl_result URLs)
         (the rest test target_url only — unchanged)
      4. Finalise: dedup → report → DB → Slack → SCAN_COMPLETED

    Usage:
        orchestrator = ScanOrchestrator(scan_id, target_url, broadcast)
        await orchestrator.run()
        # from another coroutine:
        orchestrator.cancel()
    """

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        broadcast: EventBroadcaster,
        known_account_email: str | None = None,
    ) -> None:
        self.scan_id          = scan_id
        self.target_url       = target_url
        self.broadcast        = broadcast
        self._log             = get_logger(f"orchestrator.{scan_id[:8]}")

        self._scope     = ScopeEnforcer(target_url)
        # Optional known-good account for username_enum's login differential.
        self._scope.known_account_email = known_account_email
        self._client    = _build_client()
        self._runner    = ScanRunner(scan_id, self._scope, self._client, broadcast)
        self._finaliser = ScanFinaliser(scan_id, target_url, broadcast)

    # ── Control signals (thread-safe, pass-through) ───────
    def cancel(self) -> None: self._runner.cancel()
    def pause(self)  -> None: self._runner.pause()
    def resume(self) -> None: self._runner.resume()

    # ── Main entry point ──────────────────────────────────

    async def run(self) -> None:
        """Execute the full scan lifecycle."""
        await create_scan(self.scan_id, self.target_url)
        await self._emit(WSEvent(
            event=WSEventType.SCAN_STARTED,
            scan_id=self.scan_id,
            data={"target_url": self.target_url, "total_modules": TOTAL_MODULES},
        ))
        self._log.info("Scan started → %s", self.target_url)

        try:
            # ── Step 1: Katana crawl (blocking, before modules) ──
            crawl_result = await self._run_crawl()
            if crawl_result is None:
                # Crawl failed — error already emitted, scan stopped
                return

            # Attach crawl result to scope so all modules can access it
            self._scope.crawl_result = crawl_result

            # ── Step 2: Run all modules ──────────────────────────
            findings = await self._runner.run_all()

            if self._runner._cancelled:
                counts = _count_by_severity([f.to_db_dict() for f in findings])
                await stop_scan(self.scan_id)
                await self._emit(WSEvent.scan_stopped(self.scan_id, counts))
                self._log.info("Scan stopped by user (%d findings collected)", len(findings))
                return

            # ── Step 3: Finalise ─────────────────────────────────
            await self._finaliser.finalise(
                findings,
                crawl_result=crawl_result,
                status_map=self._runner.module_status,
            )

        except Exception as exc:
            reason = f"{exc}\n{traceback.format_exc()}"
            self._log.error("Orchestrator fatal error: %s", reason)
            await fail_scan(self.scan_id, reason)
            await self._emit(WSEvent.scan_failed(self.scan_id, str(exc)))

        finally:
            # Always close the shared client — no matter what happened
            await self._client.aclose()
            self._log.debug("HTTP client closed")

    async def _emit_crawl_progress(
        self, pages_visited: int, pages_total: int, urls_found: int
    ) -> None:
        """Broadcast live crawl progress (one event per page visited)."""
        await self._emit(WSEvent.crawl_progress(
            self.scan_id, pages_visited, pages_total, urls_found,
        ))

    async def _run_crawl(self) -> CrawlResult | None:
        """
        Run the Playwright browser crawl and return CrawlResult.
        Emits CRAWL_STARTED and CRAWL_COMPLETED WS events for the frontend.
        If crawl fails: emits CRAWL_FAILED, stops scan via fail_scan, returns None.
        Tonix crawls with a real browser only — there is no Katana fallback.
        """
        await self._emit(WSEvent.crawl_started(self.scan_id, self.target_url))
        self._log.info("Browser (Playwright) crawl starting...")

        try:
            crawler      = PlaywrightCrawler(
                self._scope, client=self._client,
                progress_cb=self._emit_crawl_progress,
            )
            crawl_result = await crawler.crawl()

            await self._emit(WSEvent.crawl_completed(self.scan_id, crawl_result))
            self._log.info(
                "Crawl complete — %d URLs discovered in %.1fs",
                crawl_result.url_count,
                crawl_result.crawl_duration,
            )
            return crawl_result

        except PlaywrightCrawlError as exc:
            reason = str(exc)
            self._log.error("Browser crawl failed: %s", reason)
            await self._emit(WSEvent.crawl_failed(self.scan_id, reason))
            await fail_scan(self.scan_id, f"Browser crawl failed: {reason}")
            return None