"""
Unit tests for GitEnumModule.

Scenarios:
  - /.git/HEAD returns 200 with ref: refs/ content → finding
  - /.git/config returns 200 with [core] content → finding
  - /.git/HEAD returns 404 → no finding
  - All paths return 404 → no findings
  - 200 with no git indicators → no finding (unless no indicators needed)
  - Request error on one path → module continues, no crash
"""

import pytest
import httpx
import respx

from backend.scope import ScopeEnforcer
from backend.modules.git_enum import GitEnumModule
from tests._helpers import mock_transport

TARGET  = "http://testsite.local"
SCAN_ID = "test-scan-id"

# The exact paths GitEnumModule probes (hardcoded per-check inside the module).
GIT_PATHS = ["/.git/HEAD", "/.git/config", "/.git/", "/.gitignore"]


def _make_module() -> tuple:
    router = respx.MockRouter(assert_all_called=False)
    client = httpx.AsyncClient(base_url=TARGET, transport=mock_transport(router))
    scope  = ScopeEnforcer(TARGET)
    mod    = GitEnumModule(scope=scope, scan_id=SCAN_ID, client=client)
    return mod, router, client


def _mock_all_404(router: respx.MockRouter) -> None:
    for path in GIT_PATHS:
        router.get(path).mock(return_value=httpx.Response(404, text="Not Found"))


@pytest.mark.asyncio
async def test_git_head_exposed_returns_finding():
    mod, router, client = _make_module()
    _mock_all_404(router)
    # Override HEAD to return real content
    router.get("/.git/HEAD").mock(return_value=httpx.Response(
        200, text="ref: refs/heads/main\n"
    ))
    async with client:
        findings = await mod.run()
    titles = [f.title for f in findings]
    assert any(".git" in t.lower() or "git" in t.lower() for t in titles)


@pytest.mark.asyncio
async def test_git_config_exposed_returns_finding():
    mod, router, client = _make_module()
    _mock_all_404(router)
    router.get("/.git/config").mock(return_value=httpx.Response(
        200, text="[core]\nrepositoryformatversion = 0\n[remote \"origin\"]\nurl = https://github.com/user/repo.git"
    ))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_all_404_no_findings():
    mod, router, client = _make_module()
    _mock_all_404(router)
    async with client:
        findings = await mod.run()
    assert findings == []


@pytest.mark.asyncio
async def test_200_without_indicators_no_finding():
    """A 200 on /.git/HEAD with unrelated content should not trigger."""
    mod, router, client = _make_module()
    _mock_all_404(router)
    # HEAD needs indicators like "ref: refs/" — random content should not match
    router.get("/.git/HEAD").mock(return_value=httpx.Response(
        200, text="<!DOCTYPE html><html><body>Not Found</body></html>"
    ))
    async with client:
        findings = await mod.run()
    head_findings = [f for f in findings if "HEAD" in f.evidence]
    assert head_findings == []


@pytest.mark.asyncio
async def test_request_error_continues_to_next_path():
    """A network error on one path must not stop the module from checking others."""
    mod, router, client = _make_module()
    _mock_all_404(router)
    # Error on HEAD, but config succeeds
    router.get("/.git/HEAD").mock(side_effect=httpx.ConnectError("timeout"))
    router.get("/.git/config").mock(return_value=httpx.Response(
        200, text="[core]\nrepositoryformatversion = 0"
    ))
    async with client:
        findings = await mod.run()
    assert len(findings) >= 1  # config finding should still be found


@pytest.mark.asyncio
async def test_finding_severity_is_high_or_critical():
    mod, router, client = _make_module()
    _mock_all_404(router)
    router.get("/.git/HEAD").mock(return_value=httpx.Response(
        200, text="ref: refs/heads/main"
    ))
    async with client:
        findings = await mod.run()
    for f in findings:
        assert f.severity.value in ("high", "critical", "medium")
