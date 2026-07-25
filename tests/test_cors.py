"""
Unit tests for CorsModule (Insecure CORS Configuration).

Scenarios:
  - Attacker origin reflected + credentials      → Critical finding
  - Attacker origin reflected, no credentials    → Medium finding
  - Wildcard ACAO, no credentials                → Low finding
  - Null origin trusted                          → High finding
  - Fixed (non-reflected) ACAO                   → no finding
  - No CORS headers at all                       → no finding
  - HTTP request error                           → no crash, no finding
"""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.cors import CorsModule
from tests._helpers import mock_transport


TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"


def _make_module():
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = CorsModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


# Company scheme fixes CORS findings at Low regardless of how permissive the
# policy is (see cors.py). These tests verify detection still fires and that
# the severity stays Low across the reflected / null-origin / wildcard cases.

@pytest.mark.asyncio
async def test_reflected_origin_with_credentials_detected_low():
    mod, router, client = _make_module()

    def reflect(request):
        origin = request.headers.get("origin", "")
        return httpx.Response(200, headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        }, text="ok")

    router.get("/").mock(side_effect=reflect)
    async with client:
        findings = await mod.run()

    assert len(findings) == 1
    assert findings[0].title == "Insecure CORS Configuration"
    assert findings[0].severity.value == "low"
    assert findings[0].module == "cors"
    assert findings[0].scan_id == SCAN_ID


@pytest.mark.asyncio
async def test_reflected_origin_without_credentials_detected_low():
    mod, router, client = _make_module()

    def reflect(request):
        return httpx.Response(200, headers={
            "Access-Control-Allow-Origin": request.headers.get("origin", ""),
        }, text="ok")

    router.get("/").mock(side_effect=reflect)
    async with client:
        findings = await mod.run()

    assert len(findings) == 1
    assert findings[0].severity.value == "low"


@pytest.mark.asyncio
async def test_wildcard_without_credentials_is_low():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        200, headers={"Access-Control-Allow-Origin": "*"}, text="ok"
    ))
    async with client:
        findings = await mod.run()

    assert len(findings) == 1
    assert findings[0].severity.value == "low"


@pytest.mark.asyncio
async def test_null_origin_trusted_detected_low():
    mod, router, client = _make_module()

    def handler(request):
        if request.headers.get("origin") == "null":
            return httpx.Response(200, headers={
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Credentials": "true",
            }, text="ok")
        # Other origins: no ACAO but Vary: Origin so probing continues.
        return httpx.Response(200, headers={"Vary": "Origin"}, text="ok")

    router.get("/").mock(side_effect=handler)
    async with client:
        findings = await mod.run()

    assert len(findings) == 1
    assert findings[0].severity.value == "low"


@pytest.mark.asyncio
async def test_fixed_origin_not_reflected_no_finding():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(
        200,
        headers={"Access-Control-Allow-Origin": "https://trusted.testsite.local", "Vary": "Origin"},
        text="ok",
    ))
    async with client:
        findings = await mod.run()

    assert findings == []


@pytest.mark.asyncio
async def test_no_cors_headers_no_finding():
    mod, router, client = _make_module()
    router.get("/").mock(return_value=httpx.Response(200, headers={}, text="ok"))
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
