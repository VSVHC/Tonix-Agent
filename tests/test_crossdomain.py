"""
Unit tests for CrossDomainModule.

Scenarios:
  - crossdomain.xml with wildcard domain="*" → critical
  - crossdomain.xml exists but no wildcard → medium/high
  - clientaccesspolicy.xml with wildcard → critical
  - Both files return 404 → no findings
  - Request error → no crash
"""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.crossdomain import CrossDomainModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"

WILDCARD_CROSSDOMAIN = '''<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
  <allow-access-from domain="*"/>
</cross-domain-policy>'''

RESTRICTIVE_CROSSDOMAIN = '''<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="trusted.example.com"/>
</cross-domain-policy>'''

WILDCARD_CLIENTACCESS = '''<?xml version="1.0" encoding="utf-8"?>
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from>
        <domain uri="*"/>
      </allow-from>
    </policy>
  </cross-domain-access>
</access-policy>'''


def _make_module() -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = CrossDomainModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


@pytest.mark.asyncio
async def test_wildcard_crossdomain_is_critical():
    mod, router, client = _make_module()
    router.get("/crossdomain.xml").mock(return_value=httpx.Response(200, text=WILDCARD_CROSSDOMAIN))
    router.get("/clientaccesspolicy.xml").mock(return_value=httpx.Response(404, text=""))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1
    assert any(f.severity.value == "critical" for f in findings)


@pytest.mark.asyncio
async def test_restrictive_crossdomain_returns_finding_not_critical():
    mod, router, client = _make_module()
    router.get("/crossdomain.xml").mock(return_value=httpx.Response(200, text=RESTRICTIVE_CROSSDOMAIN))
    router.get("/clientaccesspolicy.xml").mock(return_value=httpx.Response(404, text=""))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1
    # Should not be critical since no wildcard
    critical = [f for f in findings if f.severity.value == "critical"]
    assert critical == []


MINIMAL_CROSSDOMAIN = '''<?xml version="1.0"?>
<cross-domain-policy>
</cross-domain-policy>'''

# A soft-404: server returns 200 but serves the homepage instead of a real
# policy file. The module must NOT trust the 200 — the body lacks the
# mandatory <cross-domain-policy> root tag.
SOFT_404_HTML = "<html><head><title>Home</title></head><body>Welcome</body></html>"


@pytest.mark.asyncio
async def test_file_exists_no_rules_is_medium():
    """A policy file with no access rules still discloses config → medium."""
    mod, router, client = _make_module()
    router.get("/crossdomain.xml").mock(return_value=httpx.Response(200, text=MINIMAL_CROSSDOMAIN))
    async with client:
        findings = await mod.run()
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"


@pytest.mark.asyncio
async def test_soft_404_html_not_flagged():
    """200 whose body is HTML (not a real policy file) must be ignored."""
    mod, router, client = _make_module()
    router.get("/crossdomain.xml").mock(return_value=httpx.Response(200, text=SOFT_404_HTML))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_missing_no_findings():
    mod, router, client = _make_module()
    router.get("/crossdomain.xml").mock(return_value=httpx.Response(404, text=""))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_request_error_no_crash():
    mod, router, client = _make_module()
    router.get("/crossdomain.xml").mock(side_effect=httpx.ConnectError("timeout"))
    router.get("/clientaccesspolicy.xml").mock(side_effect=httpx.ConnectError("timeout"))
    async with client:
        findings = await mod.run()
    assert findings == []
