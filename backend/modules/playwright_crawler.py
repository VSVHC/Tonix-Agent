"""
modules/playwright_crawler.py
──────────────────────────────
Real-browser web crawler (Playwright) — Tonix's replacement for Katana.

Why a browser instead of Katana:
  Katana is a static/HTML crawler that *guesses* at JavaScript by regex-mining
  bundles. It never sees the requests an app actually makes at runtime, so it
  misses:
    • API URLs built at runtime  (baseURL + '/' + id — never a literal in the JS)
    • lazy chunks / routes that only load on scroll or navigation
    • XHR/fetch that fire while the page runs
  Playwright opens the target in a real Chromium, and a single
  ``page.on("request")`` listener records EVERY URL the browser hits — the exact
  list of what the app really uses, no guessing.

What it does per page (safe core — no clicking/form-submitting on a live target):
    goto → wait for network idle → scroll (trigger lazy loads) → record every
    request → collect in-scope <a href> links → follow them (BFS, bounded).

Everything after URL-gathering is INHERITED from CrawlPipeline unchanged:
    normalize → scope filter → dedupe → classify → supplement → httpx verify.
So this class only replaces *how raw URLs are gathered*; the whole verify /
soft-404 / JS-body pipeline is reused as-is and returns the same CrawlResult.

No fallback: if Playwright isn't installed or Chromium won't launch, crawl()
raises PlaywrightCrawlError and the scan stops. Tonix crawls with a real browser
or not at all — it never falls back to Katana or any other crawler.

ponytail: first cut is passive+link-following capture. Clicking buttons and
submitting forms would raise coverage but can trigger destructive actions on a
live pentest target (logout/delete/emails) — add behind an opt-in flag later.
"""

import asyncio
import time
from collections import deque
from urllib.parse import urljoin, urlparse

from backend.config import settings
from backend.models import CrawlResult
from backend.modules.crawl_pipeline import CrawlPipeline
from backend.logger import get_logger


class PlaywrightCrawlError(Exception):
    """Raised when the browser crawl cannot run (Playwright/Chromium missing)."""
    pass


# Browser resource types that are never testable endpoints — dropped at capture
# so images/fonts/media/CSS/subtitles don't pollute the dump or the verify pass.
# Everything else (document, xhr, fetch, script, websocket, manifest, other, …)
# is kept.
_SKIP_RESOURCE_TYPES = {"image", "media", "font", "stylesheet", "texttrack"}


class PlaywrightCrawler(CrawlPipeline):
    """
    The crawler. Gathers raw URLs with a real browser (the browser-capture
    stage below), then reuses every helper on CrawlPipeline (_classify,
    _supplement, _verify_and_reconcile, _normalize, _select_user_agent, …) to
    turn them into a verified CrawlResult. Constructor ``(scope, client)`` and
    ``crawl() -> CrawlResult``.
    """

    def __init__(self, scope, client=None, progress_cb=None) -> None:
        super().__init__(scope, client=client)
        self._log = get_logger("playwright_crawler")
        # Optional async callable(pages_visited, pages_total, urls_found) for
        # live progress reporting during the browser crawl (the orchestrator
        # wires this to a WebSocket emit so the UI updates per page).
        self._progress_cb = progress_cb

    # ─────────────────────────────────────────────────────
    #  Public entry point
    # ─────────────────────────────────────────────────────

    async def crawl(self) -> CrawlResult:
        # Switch to a non-blocked User-Agent if the target's bot protection
        # blocks the default (reused from CrawlPipeline; applies to httpx AND
        # the browser context we launch below).
        await self._select_user_agent()

        started_at = time.monotonic()
        try:
            raw_urls = await self._browser_capture()
        except _PlaywrightUnavailable as exc:
            raise PlaywrightCrawlError(
                "Tonix crawl aborted — Playwright + Chromium are required but "
                f"unavailable ({exc}).\n"
                "Install them with:\n"
                "    pip install playwright\n"
                "    playwright install chromium\n"
                "Tonix crawls with a real browser only; it does not fall back to "
                "any other crawler."
            ) from exc

        crawl_duration = time.monotonic() - started_at
        self._log.info(
            "Browser capture finished in %.1fs — %d raw request URL(s)",
            crawl_duration, len(raw_urls),
        )

        # Every URL the browser actually hit is high-confidence (real navigation
        # / real XHR), so it goes into the trusted set — kept through soft-404
        # verification on catch-all SPA targets.
        native_urls = {n for n in (self._normalize(u) for u in raw_urls) if n}

        result_cr = self._classify(raw_urls, crawl_duration)
        self._log.info(
            "After normalize/scope/dedupe — pages=%d js=%d api=%d",
            result_cr.url_count, result_cr.js_count, result_cr.api_count,
        )

        # Supplemental HTML/JS mining + httpx verification — inherited unchanged.
        trusted_urls = set(native_urls)
        if self._client:
            extra, declared = await self._supplement(result_cr)
            trusted_urls |= {n for n in (self._normalize(u) for u in declared) if n}
            if extra:
                self._log.info("Supplemental discovery added %d raw ref(s)", len(extra))
                result_cr = self._classify(raw_urls + extra, crawl_duration)
            await self._verify_and_reconcile(result_cr, trusted_urls)

        self._log.info(
            "Verified crawl result — pages=%d js=%d api=%d forms=%d",
            result_cr.url_count, result_cr.js_count,
            result_cr.api_count, result_cr.form_count,
        )
        return result_cr

    # ─────────────────────────────────────────────────────
    #  Browser capture — the only Playwright-specific stage
    # ─────────────────────────────────────────────────────

    async def _browser_capture(self) -> list[str]:
        """
        Launch Chromium, BFS-visit in-scope pages, and return every request URL
        the browser fired. Raises _PlaywrightUnavailable if Playwright isn't
        installed or Chromium can't launch (→ crawl() raises PlaywrightCrawlError).
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise _PlaywrightUnavailable("playwright not installed") from exc

        captured: set[str] = set()
        visited:  set[str] = set()
        start = self._normalize(self.scope.target_url) or self.scope.target_url
        queue: deque[str] = deque([start])

        page_timeout_ms = settings.PLAYWRIGHT_PAGE_TIMEOUT * 1000

        try:
            async with async_playwright() as pw:
                try:
                    browser = await pw.chromium.launch(
                        headless=settings.PLAYWRIGHT_HEADLESS,
                        args=["--no-sandbox", "--disable-dev-shm-usage"],
                    )
                except Exception as exc:  # Chromium missing / won't launch
                    raise _PlaywrightUnavailable(f"chromium launch failed: {exc}") from exc

                context = await browser.new_context(
                    ignore_https_errors=True,           # pentest tool — hit bad TLS too
                    user_agent=self._ua_override or None,
                )
                page = await context.new_page()
                # Record every request the browser makes EXCEPT pure assets
                # (images/fonts/media/css/subtitles). We use the browser's own
                # resource-type label — authoritative, and it drops extensionless
                # assets (/avatar?id=5, tracking pixels) that a URL-suffix filter
                # misses. Blocklist not allowlist: unknown/"other" types are kept
                # so an unusual endpoint is never dropped. This only filters what
                # we *record* — the page still loads assets normally, so lazy-load
                # requests still fire.
                def _on_request(req) -> None:
                    if req.resource_type not in _SKIP_RESOURCE_TYPES:
                        captured.add(req.url)
                page.on("request", _on_request)

                while queue and len(visited) < settings.PLAYWRIGHT_MAX_PAGES:
                    url = queue.popleft()
                    if url in visited:
                        continue
                    visited.add(url)

                    # Report progress as each page BEGINS (a page load can take
                    # up to PLAYWRIGHT_PAGE_TIMEOUT seconds); emitting here keeps
                    # the UI counter moving instead of lagging a full page behind.
                    if self._progress_cb:
                        pages_total = min(
                            len(visited) + len(queue), settings.PLAYWRIGHT_MAX_PAGES
                        )
                        await self._progress_cb(len(visited), pages_total, len(captured))

                    links = await self._visit(page, url, page_timeout_ms)
                    for link in links:
                        n = self._normalize(link)
                        if n and n not in visited and self.scope.is_in_scope(n):
                            queue.append(n)

                await context.close()
                await browser.close()
        except _PlaywrightUnavailable:
            raise
        except Exception as exc:
            # Any other Playwright/runtime failure → surface as a clear crawl
            # error (crawl() turns this into PlaywrightCrawlError).
            raise _PlaywrightUnavailable(f"browser run failed: {exc}") from exc

        # Include the pages we navigated to as well — some are same-URL redirects
        # whose final address only shows up as a document request anyway, but be
        # explicit so nothing is lost.
        captured.update(visited)
        self._log.info("Visited %d page(s), captured %d request URL(s)",
                       len(visited), len(captured))
        return list(captured)

    async def _visit(self, page, url: str, timeout_ms: int) -> list[str]:
        """
        Navigate to one page, let it settle, scroll to trigger lazy loads, and
        return the in-scope <a href> links found on it. Never raises — a bad
        page just yields no links.
        """
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as exc:
            self._log.debug("goto failed for %s: %s", url, exc)
            return []

        # Let XHR/fetch that fire on load settle (best-effort; ignore timeout).
        try:
            await page.wait_for_load_state("networkidle", timeout=timeout_ms)
        except Exception:
            pass

        # Scroll in steps so lazy-loaded chunks / infinite-scroll requests fire.
        for _ in range(settings.PLAYWRIGHT_SCROLL_PASSES):
            try:
                await page.mouse.wheel(0, 4000)
                await page.wait_for_timeout(400)
            except Exception:
                break

        # Collect same-document links to follow.
        try:
            hrefs = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.getAttribute('href'))"
            )
        except Exception:
            hrefs = []

        out: list[str] = []
        for href in hrefs:
            if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            out.append(urljoin(url, href))
        return out


class _PlaywrightUnavailable(Exception):
    """Raised internally when Playwright/Chromium can't run → crawl() raises PlaywrightCrawlError."""
    pass
