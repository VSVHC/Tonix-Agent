"""
modules/base_module.py
──────────────────────
Abstract base class for all scan modules.

- Accepts a shared httpx.AsyncClient (no per-module client creation/leak)
- Client is never closed by the module (owned by the orchestrator)
- Full type hints throughout
"""

import httpx
from abc import ABC, abstractmethod
from typing import Awaitable, Callable, Optional

from backend.scope import ScopeEnforcer
from backend.models import Finding, Severity
from backend.logger import get_logger

# Called by a module to report its own completion fraction (done, total).
ProgressCallback = Callable[[str, int, int], Awaitable[None]]


class BaseModule(ABC):
    # ── Override in every subclass ───────────────────────
    name: str = "base"

    def __init__(
        self,
        scope: ScopeEnforcer,
        scan_id: str,
        client: httpx.AsyncClient,
        progress_cb: Optional[ProgressCallback] = None,
    ) -> None:
        self.scope   = scope
        self.scan_id = scan_id
        self._client = client          # shared — do NOT close in modules
        self._log    = get_logger(f"module.{self.name}")
        self._progress_cb = progress_cb

    # ─────────────────────────────────────────────────────
    #  Sub-progress — long modules report their own % here so the UI can
    #  show this test case's completion instead of the overall scan %.
    # ─────────────────────────────────────────────────────
    async def report_progress(self, done: int, total: int) -> None:
        if self._progress_cb and total > 0:
            try:
                await self._progress_cb(self.name, done, total)
            except Exception:
                pass   # progress reporting must never break a scan

    # ─────────────────────────────────────────────────────
    #  Katana-aware URL selection — shared by every module that
    #  iterates the crawl surface. Returns Katana-discovered URLs,
    #  or falls back to the root URL when no crawl result exists.
    # ─────────────────────────────────────────────────────
    def _get_urls(self) -> list[str]:
        """Return Katana-discovered URLs or fall back to root URL."""
        cr = self.scope.crawl_result
        if cr and cr.all_urls:
            return cr.all_urls
        return [self.scope.base_url + "/"]

    # ─────────────────────────────────────────────────────
    #  Abstract interface
    # ─────────────────────────────────────────────────────

    @abstractmethod
    async def run(self) -> list[Finding]:
        """
        Execute all checks for this module.
        Return a list of Finding objects (empty list = no issues found).
        """
        ...

    # ─────────────────────────────────────────────────────
    #  Scoped HTTP helpers
    # ─────────────────────────────────────────────────────

    async def get(
        self,
        path: str,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        follow_redirects: bool = True,
        raw_url: Optional[str] = None,
    ) -> httpx.Response:
        url = raw_url if raw_url else self.scope.build_url(path)
        self.scope.enforce(url)
        return await self._client.get(
            url,
            headers=headers,
            params=params,
            follow_redirects=follow_redirects,
        )

    async def post(
        self,
        path: str,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
        raw_url: Optional[str] = None,
    ) -> httpx.Response:
        url = raw_url if raw_url else self.scope.build_url(path)
        self.scope.enforce(url)
        return await self._client.post(url, data=data, json=json, headers=headers)

    async def request(
        self,
        method: str,
        path: str,
        headers: Optional[dict] = None,
        content: Optional[bytes] = None,
        raw_url: Optional[str] = None,
    ) -> httpx.Response:
        """Generic method for custom HTTP verbs (TRACE, OPTIONS, etc.)."""
        url = raw_url if raw_url else self.scope.build_url(path)
        self.scope.enforce(url)
        return await self._client.request(method, url, headers=headers, content=content)

    # ─────────────────────────────────────────────────────
    #  Redirect helper
    # ─────────────────────────────────────────────────────

    @staticmethod
    def redirected_elsewhere(response: httpx.Response, requested_path: str) -> bool:
        """
        True if a redirect occurred AND the final URL's path is DIFFERENT
        from the originally requested path — e.g. a catch-all redirect to
        the homepage or a login page. In that case the resource does not
        actually exist at the requested path.

        False if no redirect occurred, or if the only thing that changed
        was scheme/host (e.g. a site-wide http -> https redirect) while the
        path itself stayed the same — that's still a genuine hit.
        """
        if not response.history:
            return False
        final_path = response.url.path.rstrip("/") or "/"
        req_path   = requested_path.rstrip("/") or "/"
        return final_path != req_path

    # ─────────────────────────────────────────────────────
    #  Finding factory
    # ─────────────────────────────────────────────────────

    def make_finding(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: str,
        affected_urls: list[str],
        request_data: str = "",
        response_data: str = "",
        remediation: str = "",
        cvss_score: Optional[float] = None,
        cvss_vector: str = "",
    ) -> Finding:
        """Convenience method to build a Finding with scan_id pre-filled."""
        return Finding(
            scan_id=self.scan_id,
            module=self.name,
            title=title,
            severity=Severity(severity),
            description=description,
            evidence=evidence,
            affected_urls=affected_urls,
            request_data=request_data,
            response_data=response_data,
            remediation=remediation,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
        )
