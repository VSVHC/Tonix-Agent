"""
Unit tests for ClickjackingModule.

Scenarios:
  - No protection headers → finding returned
  - X-Frame-Options: DENY → no finding
  - X-Frame-Options: SAMEORIGIN → no finding
  - CSP frame-ancestors 'none' → no finding
  - CSP frame-ancestors 'self' → no finding
  - HTTP request error → no crash, no finding
"""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.clickjacking import ClickjackingModule
from tests._helpers import mock_transport


TARGET = "http://testsite.local"
SCAN_ID = "test-scan-id"


def _make_module(extra_headers: dict = {}) -> tuple[ClickjackingModule, respx.MockRouter]:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = ClickjackingModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


@pytest.mark.asyncio
async def test_no_protection_returns_finding():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(200, headers={}, text="<html/>"))
    async with client:
        findings = await mod.run()
    assert len(findings) == 1
    assert "Clickjacking" in findings[0].title
    # Module rule: absence of BOTH X-Frame-Options and CSP is rated LOW.
    assert findings[0].severity.value == "low"


@pytest.mark.asyncio
async def test_xfo_deny_no_finding():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        200, headers={"X-Frame-Options": "DENY"}, text="<html/>"
    ))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_xfo_sameorigin_no_finding():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        200, headers={"X-Frame-Options": "SAMEORIGIN"}, text="<html/>"
    ))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_csp_present_but_xfo_absent_is_vulnerable():
    # New rule: CSP present does NOT save the page — if X-Frame-Options is
    # absent, it's vulnerable.
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        200,
        headers={"Content-Security-Policy": "frame-ancestors 'none'"},
        text="<html/>"
    ))
    async with client:
        findings = await mod.run()
    assert len(findings) == 1
    assert findings[0].severity.value == "low"


@pytest.mark.asyncio
async def test_both_headers_present_no_finding():
    # X-Frame-Options present (with or without CSP) → not vulnerable.
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        200,
        headers={
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
        },
        text="<html/>"
    ))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_request_error_no_crash():
    mod, router, client = _make_module()
    router.get("/").mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_finding_has_evidence_and_remediation():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(200, headers={}, text="<html/>"))
    async with client:
        findings = await mod.run()
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence != ""
    assert f.remediation != ""
    assert f.scan_id == SCAN_ID
    assert f.module == "clickjacking"
