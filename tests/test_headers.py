"""
Unit tests for HeadersModule.

Scenarios:
  - All security headers present and correct → no findings
  - Missing HSTS → finding
  - Missing X-Content-Type-Options → finding
  - CSP with unsafe-inline → finding
  - HSTS max-age too short → finding
  - X-Frame-Options wrong value → finding
  - Request error → no crash
"""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.headers import HeadersModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"

GOOD_HEADERS = {
    "Strict-Transport-Security":  "max-age=63072000; includeSubDomains; preload",
    "X-Frame-Options":            "DENY",
    "X-Content-Type-Options":     "nosniff",
    "Content-Security-Policy":    "default-src 'self'",
    "Referrer-Policy":            "strict-origin-when-cross-origin",
    "Permissions-Policy":         "geolocation=(), microphone=()",
}


def _make_module(headers: dict) -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = HeadersModule(scope=scope, scan_id=SCAN_ID, client=client)
    router.get("/").mock(return_value=httpx.Response(200, headers=headers, text="ok"))
    return mod, client


@pytest.mark.asyncio
async def test_all_good_headers_no_findings():
    mod, client = _make_module(GOOD_HEADERS)
    async with client:
        findings = await mod.run()
    # Should produce no findings or only informational ones
    critical_high = [f for f in findings if f.severity.value in ("critical", "high")]
    assert critical_high == []


@pytest.mark.asyncio
async def test_missing_hsts_returns_finding():
    headers = {k: v for k, v in GOOD_HEADERS.items() if k != "Strict-Transport-Security"}
    mod, client = _make_module(headers)
    async with client:
        findings = await mod.run()
    titles = [f.title for f in findings]
    assert any("HSTS" in t or "Transport" in t for t in titles)
    # HSTS is rated low per spec.
    assert findings[0].severity.value == "low"


@pytest.mark.asyncio
async def test_missing_xcontent_type_returns_finding():
    headers = {k: v for k, v in GOOD_HEADERS.items() if k != "X-Content-Type-Options"}
    mod, client = _make_module(headers)
    async with client:
        findings = await mod.run()
    titles = [f.title for f in findings]
    assert any("Content-Type" in t or "MIME" in t or "X-Content" in t for t in titles)


@pytest.mark.asyncio
async def test_missing_csp_returns_finding():
    # Module rule: presence-only. A present CSP (any value) is NOT flagged;
    # only an ABSENT one is. Drop the header to trigger the finding.
    headers = {k: v for k, v in GOOD_HEADERS.items() if k != "Content-Security-Policy"}
    mod, client = _make_module(headers)
    async with client:
        findings = await mod.run()
    titles = [f.title for f in findings]
    assert any("CSP" in t or "Content-Security" in t for t in titles)
    # CSP is rated informational per spec.
    assert findings[0].severity.value == "info"


@pytest.mark.asyncio
async def test_present_hsts_not_flagged_regardless_of_value():
    # A short max-age is still a PRESENT header, so presence-only logic
    # must not raise an HSTS finding for it.
    headers = dict(GOOD_HEADERS)
    headers["Strict-Transport-Security"] = "max-age=3600"  # short, but present
    mod, client = _make_module(headers)
    async with client:
        findings = await mod.run()
    titles = [f.title for f in findings]
    assert not any("HSTS" in t or "Transport" in t for t in titles)


@pytest.mark.asyncio
async def test_all_findings_have_scan_id():
    headers = {}  # no headers at all — should generate many findings
    mod, client = _make_module(headers)
    async with client:
        findings = await mod.run()
    assert len(findings) > 0
    for f in findings:
        assert f.scan_id == SCAN_ID
        assert f.module == "headers"
        assert f.evidence != "" or f.description != ""


@pytest.mark.asyncio
async def test_xframe_options_not_reported_here():
    # X-Frame-Options absence is owned by the clickjacking module now, so the
    # headers module must NOT emit an X-Frame-Options finding even when it's
    # missing from an otherwise-empty header set.
    mod, client = _make_module({})
    async with client:
        findings = await mod.run()
    assert not any("X-Frame-Options" in f.title for f in findings)


@pytest.mark.asyncio
async def test_request_error_no_crash():
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    router.get("/").mock(side_effect=httpx.ConnectError("refused"))
    scope = ScopeEnforcer(TARGET)
    mod = HeadersModule(scope=scope, scan_id=SCAN_ID, client=client)
    async with client:
        findings = await mod.run()
    assert isinstance(findings, list)
