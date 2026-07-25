"""Unit tests for ReqSplittingModule."""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.req_splitting import ReqSplittingModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"


def _make_module() -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = ReqSplittingModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


@pytest.mark.asyncio
async def test_split_request_line_in_header_returns_finding():
    """Injected request line surfacing in a real response header → vulnerable."""
    mod, router, client = _make_module()
    router.route().mock(
        return_value=httpx.Response(
            200,
            headers={"X-Echo-Request": "GET /test HTTP/1.1"},
            text="ok",
        )
    )
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1
    assert "request splitting" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_body_reflection_not_flagged():
    """Payload reflected only in the BODY → NOT vulnerable."""
    mod, router, client = _make_module()
    router.route().mock(
        return_value=httpx.Response(
            200, headers={}, text="Echo: GET /test HTTP/1.1 (reflected in body)"
        )
    )
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_400_bad_request_not_flagged():
    """400 rejection of the CRLF payload → NOT vulnerable."""
    mod, router, client = _make_module()
    router.route().mock(
        return_value=httpx.Response(
            400, headers={"X-Echo-Request": "GET /test HTTP/1.1"}, text="Bad Request"
        )
    )
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_clean_responses_no_findings():
    mod, router, client = _make_module()
    router.route().mock(return_value=httpx.Response(200, headers={}, text="ok"))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_request_errors_no_crash():
    mod, router, client = _make_module()
    router.route().mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert isinstance(findings, list)
