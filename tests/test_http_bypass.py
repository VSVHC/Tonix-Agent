"""
Unit tests for HttpBypassModule.

Unlike the other modules, HttpBypass builds its OWN httpx clients internally
(it probes http:// on port 80 and https:// on port 443 directly), so it can't
be driven through the shared client's transport. These tests use the global
`@respx.mock` patch, which intercepts every httpx client process-wide.

Scenarios:
  - HTTP serves cleartext AND HTTPS is available → HTTP Bypass finding
  - HTTP redirects to HTTPS → not vulnerable (HTTPS enforced)
  - Port 80 refused / all requests error → no crash, no finding
"""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.http_bypass import HttpBypassModule

TARGET_HTTP = "http://testsite.local"
SCAN_ID     = "test-scan-id"


def _make_module(target: str = TARGET_HTTP):
    scope  = ScopeEnforcer(target)
    client = httpx.AsyncClient(base_url=target)
    mod    = HttpBypassModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, client


@pytest.mark.asyncio
@respx.mock
async def test_http_bypass_when_https_also_available():
    """Cleartext served on port 80 while HTTPS works → HTTP Bypass (medium)."""
    respx.get("http://testsite.local/").mock(return_value=httpx.Response(200, text="ok"))
    respx.get("https://testsite.local/").mock(return_value=httpx.Response(200, text="ok"))
    mod, client = _make_module()
    async with client:
        findings = await mod.run()
    titles = [f.title for f in findings]
    assert any("HTTP" in t or "Bypass" in t for t in titles)


@pytest.mark.asyncio
@respx.mock
async def test_http_redirects_to_https_not_vulnerable():
    """Port 80 issues a 301 to https:// → HTTPS enforced → no finding."""
    respx.get("http://testsite.local/").mock(return_value=httpx.Response(
        301, headers={"Location": "https://testsite.local/"}
    ))
    respx.get("https://testsite.local/").mock(return_value=httpx.Response(200, text="ok"))
    mod, client = _make_module()
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_all_errors_no_crash():
    """Port 80 refused → nothing to downgrade → no finding, no crash."""
    respx.route().mock(side_effect=httpx.ConnectError("refused"))
    mod, client = _make_module()
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_findings_have_required_fields():
    respx.get("http://testsite.local/").mock(return_value=httpx.Response(200, text="ok"))
    respx.get("https://testsite.local/").mock(return_value=httpx.Response(200, text="ok"))
    mod, client = _make_module()
    async with client:
        findings = await mod.run()
    for f in findings:
        assert f.scan_id == SCAN_ID
        assert f.module == "http_bypass"
        assert f.severity.value in ("critical", "high", "medium", "low", "info")
