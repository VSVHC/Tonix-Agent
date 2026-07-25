"""
Unit tests for the sitemap and robots modules.

The original combined `sitemap_robots` module was split into two independent
modules: `sitemap.SitemapModule` and `robots.RobotsModule`. Both verify by
CONTENT (a real robots.txt must contain a "User-agent:" line; a real sitemap
must contain <urlset>/<sitemapindex>) rather than trusting a bare 200.

Scenarios (assessment policy):
  - robots.txt with only Disallow paths → NOT vulnerable (info)
  - robots.txt containing an Allow directive → informational (info) finding
  - sitemap.xml with a <urlset> → info finding
  - files missing → no findings
  - request errors → no crash
"""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.robots import RobotsModule
from backend.modules.sitemap import SitemapModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"

ROBOTS_DISALLOW_ONLY = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /config\n"
ROBOTS_WITH_ALLOW    = "User-agent: *\nDisallow: /search\nAllow: /public/api\n"
SITEMAP_XML = (
    '<?xml version="1.0"?>'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    '<url><loc>http://testsite.local/</loc></url>'
    '</urlset>'
)


def _make(cls) -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = cls(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


# ── robots.txt ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_robots_disallow_only_not_vulnerable():
    """Only Disallow directives → not vulnerable, regardless of path."""
    mod, router, client = _make(RobotsModule)
    router.get("/robots.txt").mock(return_value=httpx.Response(200, text=ROBOTS_DISALLOW_ONLY))
    async with client:
        findings = await mod.run()
    assert len(findings) == 1
    assert findings[0].severity.value == "info"
    assert "not vulnerable" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_robots_allow_directive_is_informational():
    """Any Allow: directive present → informational finding."""
    mod, router, client = _make(RobotsModule)
    router.get("/robots.txt").mock(return_value=httpx.Response(200, text=ROBOTS_WITH_ALLOW))
    async with client:
        findings = await mod.run()
    assert len(findings) == 1
    assert findings[0].severity.value == "info"
    assert "allow" in findings[0].title.lower()
    assert "/public/api" in findings[0].evidence


@pytest.mark.asyncio
async def test_robots_soft_404_html_not_flagged():
    """200 whose body is HTML (no 'User-agent:' line) is not a real robots.txt."""
    mod, router, client = _make(RobotsModule)
    router.get("/robots.txt").mock(return_value=httpx.Response(
        200, text="<html><body>Home</body></html>"
    ))
    router.get("/robot.txt").mock(return_value=httpx.Response(
        200, text="<html><body>Home</body></html>"
    ))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_robots_missing_no_findings():
    mod, router, client = _make(RobotsModule)
    router.get("/robots.txt").mock(return_value=httpx.Response(404, text=""))
    router.get("/robot.txt").mock(return_value=httpx.Response(404, text=""))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_robots_request_error_no_crash():
    mod, router, client = _make(RobotsModule)
    router.get("/robots.txt").mock(side_effect=httpx.ConnectError("refused"))
    router.get("/robot.txt").mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert findings == []


# ── sitemap.xml ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_sitemap_returns_finding():
    mod, router, client = _make(SitemapModule)
    router.get("/sitemap.xml").mock(return_value=httpx.Response(200, text=SITEMAP_XML))
    async with client:
        findings = await mod.run()
    assert len(findings) == 1
    assert "sitemap" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_sitemap_missing_no_findings():
    mod, router, client = _make(SitemapModule)
    router.get("/sitemap.xml").mock(return_value=httpx.Response(404, text=""))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_sitemap_request_error_no_crash():
    mod, router, client = _make(SitemapModule)
    router.route().mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert findings == []
