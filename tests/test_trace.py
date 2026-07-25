"""
Unit tests for TraceModule.

Scenarios:
  - Server returns 200 and echoes TRACE → vulnerable
  - Server returns 200 and echoes probe header → vulnerable
  - Server returns 405 → not vulnerable
  - Server returns 200 but empty body → flagged (status-only)
  - Request error → no crash
"""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.trace import TraceModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"


def _make_module() -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = TraceModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


@pytest.mark.asyncio
async def test_trace_echo_returns_finding():
    mod, router, client = _make_module()
    router.request("TRACE", "/").mock(return_value=httpx.Response(
        200, text="TRACE / HTTP/1.1\nX-PentestAgent-Probe: trace-test"
    ))
    async with client:
        findings = await mod.run()
    assert len(findings) == 1
    assert "TRACE" in findings[0].title


@pytest.mark.asyncio
async def test_trace_405_no_finding():
    mod, router, client = _make_module()
    router.request("TRACE", "/").mock(return_value=httpx.Response(405, text="Method Not Allowed"))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_trace_200_empty_body_not_flagged():
    """
    A bare 200 with no echoed request data is NOT trusted — SPA catch-all /
    soft-404 routing returns 200 for almost any method. The module requires
    proof the request was echoed back, so an empty body yields no finding.
    """
    mod, router, client = _make_module()
    router.request("TRACE", "/").mock(return_value=httpx.Response(200, text=""))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_trace_request_error_no_crash():
    mod, router, client = _make_module()
    router.request("TRACE", "/").mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_trace_finding_severity_is_low():
    mod, router, client = _make_module()
    router.request("TRACE", "/").mock(return_value=httpx.Response(
        200, text="TRACE echoed"
    ))
    async with client:
        findings = await mod.run()
    # Module rates XST/TRACE as LOW.
    assert findings[0].severity.value == "low"
