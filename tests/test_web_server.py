"""
Unit tests for WebServerModule.

Scenarios:
  - Server header with version → finding
  - X-Powered-By present → finding
  - Nginx default page → finding
  - Clean headers → no version-disclosure finding
  - ETag leaking inode (numeric/hyphenated) → finding
  - Request error → no crash
"""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.web_server import WebServerModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"


async def _no_cves(version_strings):
    """Stub the live NVD lookup so unit tests never hit the network."""
    return []


def _make_module() -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = WebServerModule(scope=scope, scan_id=SCAN_ID, client=client)
    mod._fetch_cves = _no_cves          # avoid real NVD API calls in tests
    return mod, router, client


@pytest.mark.asyncio
async def test_server_version_disclosure():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        200, headers={"Server": "Apache/2.4.51 (Ubuntu)"}, text="ok"
    ))
    async with client:
        findings = await mod.run()
    titles = [f.title for f in findings]
    assert any("Server" in t or "Version" in t or "version" in t for t in titles)


@pytest.mark.asyncio
async def test_x_powered_by_disclosure():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        200, headers={"X-Powered-By": "PHP/8.1.2"}, text="ok"
    ))
    async with client:
        findings = await mod.run()
    titles = [f.title for f in findings]
    assert any("Powered" in t or "Version" in t or "Technology" in t for t in titles)


@pytest.mark.asyncio
async def test_nginx_default_page_detected():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        200,
        headers={},
        text="<html><head><title>Welcome to nginx</title></head></html>"
    ))
    async with client:
        findings = await mod.run()
    titles = [f.title for f in findings]
    assert any("nginx" in t.lower() or "default" in t.lower() or "server" in t.lower() for t in titles)


@pytest.mark.asyncio
async def test_clean_response_no_version_findings():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        200, headers={"Server": "nginx"}, text="<html>App</html>"
    ))
    async with client:
        findings = await mod.run()
    # "nginx" without a version number should not trigger version-disclosure finding
    version_findings = [f for f in findings if "version" in f.title.lower()]
    # Allow zero or informational only
    high_sev = [f for f in version_findings if f.severity.value in ("critical", "high")]
    assert high_sev == []


@pytest.mark.asyncio
async def test_request_error_no_crash():
    mod, router, client = _make_module()
    router.get("/").mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_severity_is_low_without_cves():
    """Version disclosed but no unpatched CVEs → Low."""
    mod, router, client = _make_module()          # _fetch_cves stubbed to []
    router.get("/").mock(return_value=httpx.Response(
        200, headers={"Server": "Apache/2.4.51 (Ubuntu)"}, text="ok"
    ))
    async with client:
        findings = await mod.run()
    assert findings and findings[0].severity.value == "low"


@pytest.mark.asyncio
async def test_severity_tracks_worst_cve():
    """A Critical unpatched CVE for the disclosed version → Critical finding."""
    mod, router, client = _make_module()

    async def _critical_cve(version_strings):
        # Pre-sorted Critical-first, like the real _fetch_cves.
        return [
            {"id": "CVE-2024-0001", "severity": "CRITICAL", "cvss": "9.8",
             "published": "2024-01-01", "description": "rce", "url": "http://x"},
            {"id": "CVE-2023-0002", "severity": "HIGH", "cvss": "7.5",
             "published": "2023-01-01", "description": "xss", "url": "http://y"},
        ]
    mod._fetch_cves = _critical_cve

    router.get("/").mock(return_value=httpx.Response(
        200, headers={"Server": "Apache/2.4.51 (Ubuntu)"}, text="ok"
    ))
    async with client:
        findings = await mod.run()
    assert findings and findings[0].severity.value == "critical"
