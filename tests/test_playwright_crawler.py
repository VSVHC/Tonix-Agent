"""
Unit tests for PlaywrightCrawler.

No real browser or network: _browser_capture is monkeypatched to return a fixed
list of URLs (as a real Chromium run would), and the crawler is built with
client=None so the httpx supplement/verify stages are skipped. This exercises
the inherited normalize → scope → dedupe → classify pipeline and the
Katana-fallback path.
"""

import pytest

from backend.scope import ScopeEnforcer
from backend.modules.playwright_crawler import (
    PlaywrightCrawler, PlaywrightCrawlError, _PlaywrightUnavailable,
)

TARGET = "http://testsite.local"


def _crawler() -> PlaywrightCrawler:
    scope = ScopeEnforcer(TARGET)
    return PlaywrightCrawler(scope, client=None)   # client=None → skip verify/supplement


@pytest.mark.asyncio
async def test_capture_urls_are_classified(monkeypatch):
    """Raw browser-captured URLs land in the right CrawlResult buckets."""
    captured = [
        f"{TARGET}/",
        f"{TARGET}/about",
        f"{TARGET}/api/v1/users",          # → api_endpoints
        f"{TARGET}/static/app.js",         # → js_files
        f"{TARGET}/static/logo.png",       # static asset → dropped
        f"{TARGET}/login",                 # → forms (form path hint)
        f"{TARGET}/about",                 # duplicate → deduped
        "https://evil.example.com/x",      # out of scope → dropped
    ]

    async def fake_capture(self):
        return captured

    monkeypatch.setattr(PlaywrightCrawler, "_browser_capture", fake_capture)

    cr = await _crawler().crawl()

    assert f"{TARGET}/about" in cr.all_urls
    assert f"{TARGET}/api/v1/users" in cr.api_endpoints
    assert f"{TARGET}/static/app.js" in cr.js_files
    assert f"{TARGET}/login" in cr.forms
    # dropped:
    assert f"{TARGET}/static/logo.png" not in cr.all_urls
    assert all("evil.example.com" not in u for u in cr.all_urls)
    # deduped:
    assert cr.all_urls.count(f"{TARGET}/about") == 1


@pytest.mark.asyncio
async def test_raises_when_browser_unavailable(monkeypatch):
    """If Playwright/Chromium can't run, crawl() raises — no Katana fallback."""
    async def boom(self):
        raise _PlaywrightUnavailable("no chromium")

    monkeypatch.setattr(PlaywrightCrawler, "_browser_capture", boom)

    with pytest.raises(PlaywrightCrawlError, match="Playwright"):
        await _crawler().crawl()
