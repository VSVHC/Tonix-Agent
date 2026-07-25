"""Unit tests for UsernameEnumModule."""

import pytest
import httpx
import respx
from urllib.parse import unquote

from backend.scope import ScopeEnforcer
from backend.modules.username_enum import UsernameEnumModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"
KNOWN   = "realuser@example.com"          # a "known-good" account for differential

HTML_WITH_LOGIN = """<html><body>
<form action="/login" method="post">
  <input type="text" name="username"/>
  <input type="password" name="password"/>
  <button type="submit">Login</button>
</form>
</body></html>"""

ENUM_RESPONSE       = "User not found. Please check your email."
GENERIC_RESPONSE    = "Invalid username or password."
NO_FORM_PAGE        = "<html><body><h1>Welcome</h1><p>No login here.</p></body></html>"


def _make_module(known_email: str | None = None) -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    scope.known_account_email = known_email     # None = phrase-only fallback
    mod    = UsernameEnumModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


@pytest.mark.asyncio
async def test_enumeration_message_returns_finding():
    mod, router, client = _make_module()
    # The module probes login paths like /login (not the homepage): GET fetches
    # the form, POST submits the test credentials.
    router.get("/login").mock(return_value=httpx.Response(200, text=HTML_WITH_LOGIN))
    router.post("/login").mock(return_value=httpx.Response(200, text=ENUM_RESPONSE))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1
    assert any("enum" in f.title.lower() or "username" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_generic_message_no_finding():
    mod, router, client = _make_module()
    router.get("/login").mock(return_value=httpx.Response(200, text=HTML_WITH_LOGIN))
    router.post("/login").mock(return_value=httpx.Response(200, text=GENERIC_RESPONSE))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_no_login_form_no_finding():
    mod, router, client = _make_module()
    router.get("/login").mock(return_value=httpx.Response(200, text=NO_FORM_PAGE))
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_request_error_no_crash():
    mod, router, client = _make_module()
    router.get("/login").mock(side_effect=httpx.ConnectError("refused"))
    async with client:
        findings = await mod.run()
    assert isinstance(findings, list)


# ── Differential engine (with a known-good account) ──────────

@pytest.mark.asyncio
async def test_differential_detects_with_known_account():
    """
    With a known account, the module compares it against a random nonexistent
    account. Even though NEITHER response contains a revealing phrase, a
    consistent difference (here: response length) is flagged.
    """
    mod, router, client = _make_module(known_email=KNOWN)
    router.get("/login").mock(return_value=httpx.Response(200, text=HTML_WITH_LOGIN))

    def responder(request: httpx.Request) -> httpx.Response:
        body = unquote(request.content.decode())
        if KNOWN in body:                       # the account that "exists"
            return httpx.Response(200, text="Dashboard " * 50)   # long page
        return httpx.Response(200, text="Nope")                  # short page

    router.post("/login").mock(side_effect=responder)
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1
    assert "differential" in findings[0].evidence.lower()


@pytest.mark.asyncio
async def test_no_difference_with_known_account_no_finding():
    """Identical responses for both accounts → no leak → no finding."""
    mod, router, client = _make_module(known_email=KNOWN)
    router.get("/login").mock(return_value=httpx.Response(200, text=HTML_WITH_LOGIN))
    router.post("/login").mock(return_value=httpx.Response(200, text="Same page for everyone"))
    async with client:
        findings = await mod.run()
    assert findings == []


# ── Regression: bare /forgot path + decoy-form skipping ──────

# A search form sits ABOVE the real reset form. The module must (a) reach the
# bare "/forgot" path and (b) submit the form that actually has the email field,
# not the first (search) form on the page.
HTML_FORGOT_WITH_DECOY = """<html><body>
<form action="/search" method="get">
  <input type="text" name="q"/>
  <button type="submit">Search</button>
</form>
<form action="/forgot" method="post">
  <input type="email" name="email"/>
  <input type="hidden" name="csrf" value="abc123"/>
  <button type="submit">Reset</button>
</form>
</body></html>"""


@pytest.mark.asyncio
async def test_forgot_path_and_decoy_form_returns_finding():
    mod, router, client = _make_module()
    router.get("/forgot").mock(return_value=httpx.Response(200, text=HTML_FORGOT_WITH_DECOY))

    def responder(request: httpx.Request) -> httpx.Response:
        # The reset form's email field must be the one submitted (not "q").
        assert "email=" in unquote(request.content.decode())
        return httpx.Response(200, text="No User found with that email address")

    router.post("/forgot").mock(side_effect=responder)
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1
    assert any("forgot" in f.title.lower() or "enum" in f.title.lower() for f in findings)


# ── Regression: submit to the form's action, not the page URL ─

# The reset page lives at /forgot but its form posts to a separate handler,
# /processForgot. The revealing message is returned ONLY by the handler.
HTML_FORGOT_SEPARATE_ACTION = """<html><body>
<form action="/processForgot" method="post">
  <input type="email" name="email"/>
</form>
</body></html>"""


@pytest.mark.asyncio
async def test_posts_to_form_action_not_page_url():
    mod, router, client = _make_module()
    router.get("/forgot").mock(return_value=httpx.Response(200, text=HTML_FORGOT_SEPARATE_ACTION))
    # Posting to the PAGE url must NOT be how it's detected — only the handler leaks.
    router.post("/forgot").mock(return_value=httpx.Response(200, text="Invalid username or password."))
    router.post("/processForgot").mock(
        return_value=httpx.Response(200, text="No User found with that email address"))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1, "module should post to /processForgot (the form action) and detect the leak"
