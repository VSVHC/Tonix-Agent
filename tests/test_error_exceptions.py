"""Unit tests for ErrorExceptionsModule."""

import pytest
import httpx
import respx

from backend.config import settings
from backend.scope import ScopeEnforcer
from backend.modules.error_exceptions import ErrorExceptionsModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"

PYTHON_TRACEBACK = "Traceback (most recent call last):\n  File 'app.py', line 42, in handler\nKeyError: 'user_id'"
PHP_ERROR        = "<b>Fatal error</b>: Uncaught Exception in /var/www/app.php:12"
CLEAN_PAGE       = "<html><body>Oops, page not found.</body></html>"


@pytest.fixture(autouse=True)
def _fast_rate_limit(monkeypatch):
    # This module throttles outbound requests; raise the limit so the many
    # payload probes per URL don't slow the test suite down.
    monkeypatch.setattr(settings, "ERROR_MODULE_RATE_LIMIT", 10000, raising=False)


def _make_module() -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = ErrorExceptionsModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


@pytest.mark.asyncio
async def test_python_traceback_returns_finding():
    mod, router, client = _make_module()
    router.route().mock(return_value=httpx.Response(500, text=PYTHON_TRACEBACK))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1
    assert any("stack" in f.title.lower() or "trace" in f.title.lower()
               or "error" in f.title.lower() or "exception" in f.title.lower()
               for f in findings)


@pytest.mark.asyncio
async def test_php_error_returns_finding():
    mod, router, client = _make_module()
    router.route().mock(return_value=httpx.Response(200, text=PHP_ERROR))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_clean_error_page_no_finding():
    mod, router, client = _make_module()
    router.route().mock(return_value=httpx.Response(404, text=CLEAN_PAGE))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_request_error_no_crash():
    mod, router, client = _make_module()
    router.route().mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert isinstance(findings, list)
