"""Unit tests for JsEnumModule."""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.models import CrawlResult
from backend.modules.js_enum import JsEnumModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"

APP_JS    = f"{TARGET}/static/app.js"
VENDOR_JS = f"{TARGET}/static/vendor.js"

JS_WITH_SECRETS = """
var config = {
    api_key: 'AIzaSyD-9tSrke72I6e3pcMaR53GDwSCQEHB5k8',
    api_endpoint: '/api/v2/users'
};
"""

JS_CLEAN = "var app = { version: '1.0', debug: false };"


def _make_module(js_files=None) -> tuple:
    """
    Build a JsEnumModule. js_enum reads its JS URLs from the Katana crawl
    result (crawl_result.js_files), NOT by scraping the homepage — so tests
    seed the crawl result directly.
    """
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    if js_files is not None:
        scope.crawl_result = CrawlResult(js_files=list(js_files))
    mod    = JsEnumModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


@pytest.mark.asyncio
async def test_google_api_key_returns_finding():
    mod, router, client = _make_module(js_files=[APP_JS, VENDOR_JS])
    router.get("/static/app.js").mock(return_value=httpx.Response(200, text=JS_WITH_SECRETS))
    router.get("/static/vendor.js").mock(return_value=httpx.Response(200, text=JS_CLEAN))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1
    assert any("api" in f.title.lower() or "key" in f.title.lower() or "secret" in f.title.lower()
               for f in findings)


@pytest.mark.asyncio
async def test_clean_js_no_finding():
    mod, router, client = _make_module(js_files=[APP_JS, VENDOR_JS])
    router.get("/static/app.js").mock(return_value=httpx.Response(200, text=JS_CLEAN))
    router.get("/static/vendor.js").mock(return_value=httpx.Response(200, text=JS_CLEAN))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_no_js_files_no_finding():
    # No crawl result → js_enum has nothing to scan and skips entirely.
    mod, router, client = _make_module(js_files=[])
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_js_fetch_error_no_crash():
    mod, router, client = _make_module(js_files=[APP_JS, VENDOR_JS])
    router.get("/static/app.js").mock(side_effect=httpx.ConnectError("refused"))
    router.get("/static/vendor.js").mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert isinstance(findings, list)
