"""Unit tests for HostHeaderModule."""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.host_header import HostHeaderModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"


def _make_module() -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = HostHeaderModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


@pytest.mark.asyncio
async def test_reflected_host_returns_finding():
    mod, router, client = _make_module()
    # Server reflects the injected Host header value (example.com) in the body
    router.get("/").mock(return_value=httpx.Response(
        200, text="<html>Redirect to http://example.com/path</html>"
    ))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1
    assert any("host" in f.title.lower() or "injection" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_no_reflection_no_finding():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        200, text="<html><body>Welcome to our site</body></html>"
    ))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_reflected_in_location_header_returns_finding():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        301,
        headers={"Location": "http://example.com/"},
        text=""
    ))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_request_error_no_crash():
    mod, router, client = _make_module()
    router.get("/").mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert isinstance(findings, list)
