"""Unit tests for ResSplittingModule."""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.res_splitting import ResSplittingModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"


def _make_module() -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = ResSplittingModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


@pytest.mark.asyncio
async def test_injected_location_header_returns_finding():
    """A real injected Location:https://example.com header → vulnerable."""
    mod, router, client = _make_module()
    router.route().mock(
        return_value=httpx.Response(
            302,
            headers={"Location": "https://example.com"},
            text="",
        )
    )
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1
    assert "response splitting" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_injected_set_cookie_returns_finding():
    """A real injected Set-Cookie:test=1 header → vulnerable."""
    mod, router, client = _make_module()
    router.route().mock(
        return_value=httpx.Response(200, headers={"Set-Cookie": "test=1"}, text="ok")
    )
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_body_reflection_not_flagged():
    """Payload reflected in the BODY (not a real header) → NOT vulnerable."""
    mod, router, client = _make_module()
    router.route().mock(
        return_value=httpx.Response(
            200, headers={}, text="You searched for: %0d%0aX-Test:123 (nothing found)"
        )
    )
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_400_bad_request_not_flagged():
    """400 rejection — even if a matching header is present — is NOT flagged."""
    mod, router, client = _make_module()
    router.route().mock(
        return_value=httpx.Response(400, headers={"Set-Cookie": "test=1"}, text="Bad Request")
    )
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_clean_redirect_no_finding():
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
