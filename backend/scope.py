"""
scope.py
────────
Scope enforcement layer.
Every outbound request from any module MUST pass through
`enforce()` before being sent. If it fails, the request
is blocked and logged — no exceptions.
"""

import tldextract
from urllib.parse import urlparse
from typing import Optional, TYPE_CHECKING

from backend.logger import get_logger

# Avoid circular import — CrawlResult is only used for type hint
if TYPE_CHECKING:
    from backend.models import CrawlResult

log = get_logger(__name__)


class ScopeEnforcer:
    """
    Validates that all test requests stay within the approved target.

    On initialisation the enforcer extracts:
      - the exact host  (e.g. app.example.com)
      - the registered domain (e.g. example.com)

    During a scan every URL is checked against these values
    before the HTTP call is made.

    After Katana crawl completes, `crawl_result` is populated
    by the orchestrator and is available to all modules via
    self.scope.crawl_result.
    """

    def __init__(self, target_url: str) -> None:
        self.target_url = target_url.rstrip("/")
        parsed = urlparse(self.target_url)

        self.target_scheme: str         = parsed.scheme.lower()
        self.target_host: str           = parsed.hostname or ""
        self.target_port: Optional[int] = parsed.port

        extracted = tldextract.extract(self.target_url)
        self.registered_domain: str = (
            f"{extracted.domain}.{extracted.suffix}"
            if extracted.suffix else extracted.domain
        )

        self._violations: list[str] = []

        # ── Katana crawl result (set by orchestrator after crawl) ──
        # Type annotated as Optional to avoid import at runtime.
        # Modules access this as: self.scope.crawl_result
        self.crawl_result: Optional["CrawlResult"] = None

        # ── Optional known-good account (set by orchestrator from the scan
        # request). Consumed by username_enum for its login-form differential
        # check. None means "not provided".
        self.known_account_email: Optional[str] = None

        log.debug("ScopeEnforcer initialised for %s", self.target_host)

    # ─────────────────────────────────────────────────────
    #  Public API
    # ─────────────────────────────────────────────────────

    def is_in_scope(self, url: str) -> bool:
        """
        Returns True only if `url` stays within the approved target's own
        domain (subpaths always allowed):

          - the exact target host, and its `www.` variant;
          - if SCOPE_ALLOW_SUBDOMAINS is enabled, ANY subdomain that shares the
            target's registered domain (asset., static., cdn.<domain>, …) —
            same organisation, and where SPA JS bundles / assets typically live;
          - else if SCOPE_ALLOW_API_SUBDOMAIN is enabled, just `api.<domain>`.

        Third-party hosts on a DIFFERENT registered domain (e.g. a shared CDN)
        are always rejected.
        """
        try:
            from backend.config import settings

            parsed = urlparse(url)
            request_host = (parsed.hostname or "").lower()

            if request_host == self.target_host:
                return True

            # Allow www. prefix variant of the same host
            stripped        = request_host.removeprefix("www.")
            target_stripped = self.target_host.removeprefix("www.")
            if stripped == target_stripped:
                return True

            # Allow any subdomain sharing the target's registered domain (opt-in).
            # Uses tldextract so multi-part suffixes (.co.uk, .com.au) are handled.
            if settings.SCOPE_ALLOW_SUBDOMAINS and self.registered_domain:
                req = tldextract.extract(url)
                req_registered = (
                    f"{req.domain}.{req.suffix}" if req.suffix else req.domain
                )
                if req_registered and req_registered == self.registered_domain:
                    return True

            # Otherwise allow only the api.<registered_domain> subdomain (opt-in)
            elif (
                settings.SCOPE_ALLOW_API_SUBDOMAIN
                and self.registered_domain
                and request_host == f"api.{self.registered_domain}"
            ):
                return True

            self._violations.append(url)
            log.warning("Scope violation: %s (target: %s)", url, self.target_host)
            return False

        except Exception as exc:
            self._violations.append(url)
            log.error("Scope check error for %r: %s", url, exc)
            return False

    def enforce(self, url: str) -> str:
        """
        Returns the URL if in scope.
        Raises ScopeViolationError if out of scope.
        """
        if not self.is_in_scope(url):
            raise ScopeViolationError(
                f"OUT-OF-SCOPE request blocked: {url!r}\n"
                f"Approved target: {self.target_host}"
            )
        return url

    def build_url(self, path: str) -> str:
        """
        Safely construct a URL by appending a path to the target base.
        Ensures the path starts with / and the result is always in scope.
        """
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.target_scheme}://{self.target_host}"
        if self.target_port:
            url += f":{self.target_port}"
        url += path
        return self.enforce(url)

    @property
    def base_url(self) -> str:
        url = f"{self.target_scheme}://{self.target_host}"
        if self.target_port:
            url += f":{self.target_port}"
        return url

    @property
    def violations(self) -> list[str]:
        return list(self._violations)

    def __repr__(self) -> str:
        return f"<ScopeEnforcer target={self.target_host!r}>"


class ScopeViolationError(Exception):
    """Raised when a module attempts to request an out-of-scope URL."""
    pass
