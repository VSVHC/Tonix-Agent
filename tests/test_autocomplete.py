"""Unit tests for AutocompleteModule."""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.autocomplete import AutocompleteModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"

# Password field explicitly sets autocomplete="on" → vulnerable.
HTML_VULNERABLE = """<html><body>
<form action="/login" method="post">
  <input type="text" name="username"/>
  <input type="password" name="password" autocomplete="on"/>
</form>
</body></html>"""

# Password field explicitly "off" → safe.
HTML_SAFE = """<html><body>
<form action="/login" method="post">
  <input type="text" name="username"/>
  <input type="password" name="password" autocomplete="off"/>
</form>
</body></html>"""

# Password field with NO autocomplete attribute → now treated as safe.
HTML_MISSING = """<html><body>
<form action="/login" method="post">
  <input type="text" name="username"/>
  <input type="password" name="password"/>
</form>
</body></html>"""

HTML_NO_FORMS = "<html><body><h1>Welcome</h1></body></html>"


def _make_module() -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = AutocompleteModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


@pytest.mark.asyncio
async def test_vulnerable_autocomplete_returns_finding():
    mod, router, client = _make_module()
    router.get("/login").mock(return_value=httpx.Response(200, text=HTML_VULNERABLE))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1
    assert any("autocomplete" in f.title.lower() for f in findings)
    # Severity is informational per spec.
    assert findings[0].severity.value == "info"


@pytest.mark.asyncio
async def test_autocomplete_off_no_finding():
    mod, router, client = _make_module()
    router.get("/login").mock(return_value=httpx.Response(200, text=HTML_SAFE))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_missing_autocomplete_is_safe():
    # A password field with no autocomplete attribute is NOT flagged.
    mod, router, client = _make_module()
    router.get("/login").mock(return_value=httpx.Response(200, text=HTML_MISSING))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_no_forms_no_finding():
    mod, router, client = _make_module()
    router.get("/login").mock(return_value=httpx.Response(200, text=HTML_NO_FORMS))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_request_error_no_crash():
    mod, router, client = _make_module()
    router.get("/login").mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert findings == []
