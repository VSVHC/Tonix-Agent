"""Unit tests for DirectoryListingModule."""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.directory_listing import DirectoryListingModule, DIRECTORIES_TO_PROBE
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"

NGINX_LISTING = "<html><head><title>Index of /uploads/</title></head><body>Parent Directory</body></html>"
NORMAL_PAGE   = "<html><head><title>App</title></head><body>Welcome</body></html>"


def _make_module() -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = DirectoryListingModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


def _mock_all_403(router):
    for path in DIRECTORIES_TO_PROBE:
        router.get(path).mock(return_value=httpx.Response(403, text="Forbidden"))


def _vulnerable(findings):
    """Only the real 'Open Directory Listing' hits; the module emits these at
    fixed 'low' severity (company scheme) plus info-level 'not vulnerable'
    notes for 403 and normal pages."""
    return [f for f in findings if f.severity.value in ("high", "medium", "low")]


@pytest.mark.asyncio
async def test_directory_listing_detected():
    mod, router, client = _make_module()
    _mock_all_403(router)
    router.get("/uploads/").mock(return_value=httpx.Response(200, text=NGINX_LISTING))
    async with client:
        findings = await mod.run()
    vuln = _vulnerable(findings)
    assert len(vuln) >= 1
    assert any("directory" in f.title.lower() or "listing" in f.title.lower() for f in vuln)


@pytest.mark.asyncio
async def test_normal_200_not_flagged():
    mod, router, client = _make_module()
    # Every probed directory serves a normal page → no listing exposed.
    for path in DIRECTORIES_TO_PROBE:
        router.get(path).mock(return_value=httpx.Response(200, text=NORMAL_PAGE))
    async with client:
        findings = await mod.run()
    assert _vulnerable(findings) == []


@pytest.mark.asyncio
async def test_all_403_no_findings():
    mod, router, client = _make_module()
    _mock_all_403(router)
    async with client:
        findings = await mod.run()
    # 403 = directory protected → no listing vulnerability.
    assert _vulnerable(findings) == []


@pytest.mark.asyncio
async def test_request_error_no_crash():
    mod, router, client = _make_module()
    router.route().mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert isinstance(findings, list)
