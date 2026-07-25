"""
modules/error_exceptions.py
────────────────────────────
Checks if the application leaks stack traces, exception details,
or debug information in error responses.

Test payloads:
  A fixed list of malformed / non-existent path segments (PATH_PAYLOADS) is
  appended to every crawled URL — traversal sequences, null bytes, encoded
  angle brackets, template-injection markers ({{7*7}}, ${7*7}), sensitive
  filenames (.htpasswd, web.config, database.sql), and invalid identifiers
  (/users/-1, /users/null). Plus one invalid HTTP method probe on the first
  URL. Any response carrying a known verbose-error signature
  (ERROR_INDICATORS) is flagged as exception disclosure.

Rate limiting:
  All outbound requests in this module go through _throttle(), which
  enforces settings.ERROR_MODULE_RATE_LIMIT (requests/second). Without
  it, the payload requests per crawled URL fire back-to-back with no
  delay, which can trip a target's WAF/IDS or overload a small site.

Katana integration:
  Iterates ALL URLs discovered by Katana instead of only testing /.
  Collects all affected URLs and raises a single aggregated finding.
"""

import asyncio
import re
import time
import httpx
from backend.config import settings
from backend.modules.base_module import BaseModule
from backend.models import Finding


# Precise verbose-error / stack-trace signatures.
#
# These are specific, multi-token strings that only appear in genuine framework
# error output — NOT single generic words like "undefined" or "exception" that
# occur all the time in ordinary page text and (minified) JavaScript. The old
# generic list produced false positives: e.g. "undefined" matched
# `decPlaces === undefined` inside a normal number-formatting <script>. Every
# match here is a real error-page fingerprint.
ERROR_INDICATORS = [
    "traceback (most recent call last)",
    "stack trace:",
    "fatal error:",
    "parse error:",
    "uncaught exception",
    "exception in thread",
    "call stack:",
    ".php on line",
    "<b>warning</b>:",
    "<b>fatal error</b>:",
    "sqlstate[",
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "mysql_fetch",
    "pg_query(",
    "supplied argument is not a valid",
    "microsoft ole db provider",
    "odbc drivers error",
    "unexpected t_",
    "cannot use a scalar value as an array",
    "django.core.exceptions",
    "werkzeug.exceptions",
    "org.springframework",
    "system.web.httpexception",
    "java.lang.",
    "at java.",
    "ruby on rails",
    "actioncontroller::",
]

# JavaScript blocks are stripped before matching so minified/library JS (which
# routinely contains words like "undefined", "error", "exception") can never
# trigger a verbose-error finding.
_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)


class ErrorExceptionsModule(BaseModule):
    name = "error_exceptions"

    # Malformed / non-existent path segments appended to each URL to trigger
    # verbose errors, path-traversal leaks, template-injection errors, and
    # invalid-identifier handler exceptions.
    PATH_PAYLOADS = [
        "/doesnotexist123",
        "/<>",
        "/%3C%3E",
        "/%00",
        "/..%2f..%2f",
        "/..%252f..%252f",
        "/../",
        "/../../",
        "/NUL",
        "/~",
        "/.htaccess",
        "/.htpasswd",
        "/.git/config",
        "/web.config",
        "/backup.zip",
        "/config.bak",
        "/database.sql",
        "/{{7*7}}",
        "/${7*7}",
        "/users/null",
        "/users/undefined",
        "/users/-1",
        "/users/999999999999999999",
    ]

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        affected: list[dict]   = []

        urls = self._get_urls()

        total = len(urls)
        done  = 0
        await self.report_progress(0, total)

        for url in urls:
            base = url.rstrip("/")

            # 1 — Path-based error triggers
            for path in self.PATH_PAYLOADS:
                triggered = await self._probe(f"{base}{path}", "GET")
                if triggered:
                    affected.append(triggered)
                    break   # one hit per URL is enough

            # 2 — Invalid method trigger (on first URL only to avoid noise)
            if url == urls[0]:
                triggered = await self._probe(url, "INVALIDMETHOD")
                if triggered:
                    affected.append(triggered)

            done += 1
            await self.report_progress(done, total)

        if affected:
            evidence = "\n\n".join(
                f"URL: {a['url']}\n"
                f"Method: {a['method']}\n"
                f"HTTP Status: {a['status']}\n"
                f"Indicator matched: {a['indicator']}\n"
                f"Response snippet:\n{a['snippet']}"
                for a in affected[:10]
            )
            findings.append(self.make_finding(
                title="Verbose Error Messages / Exception Disclosure",
                severity="medium",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                description=(
                    f"The application returns verbose error messages or stack traces "
                    f"on {len(affected)} URL(s) when sent malformed input. "
                    "This can expose internal application structure, file paths, "
                    "database queries, and technology stack details to an attacker."
                ),
                evidence=(
                    f"Affected URLs ({len(affected)} total):\n\n{evidence}"
                    + (f"\n\n...and {len(affected) - 10} more." if len(affected) > 10 else "")
                ),
                affected_urls=[a["url"] for a in affected],
                request_data=(
                    f"GET <url><error_payload> HTTP/1.1\n"
                    f"Host: {self.scope.target_host}\n"
                    f"Cookie: <session_cookie>"
                ),
                response_data=affected[0]["snippet"] if affected else "",
                remediation=(
                    "Implement a global error handler that returns generic error pages.\n"
                    "Never expose stack traces, file paths, or exception details in production.\n"
                    "Set environment to 'production' and disable debug mode.\n"
                    "Log detailed errors server-side only — return 500 with a reference ID."
                ),
            ))

        return findings

    async def _probe(self, url: str, method: str) -> dict | None:
        """
        Send a single error-trigger request and check for verbose output.
        Returns a dict with evidence if vulnerable, None otherwise.
        """
        try:
            if not self.scope.is_in_scope(url):
                return None

            await self._throttle()
            if method == "INVALIDMETHOD":
                response = await self._client.request(method, url)
            else:
                response = await self.get(path="", raw_url=url)

            # Strip <script>…</script> so library/minified JS can't trip a
            # generic word match — the #1 source of false positives here.
            clean      = _SCRIPT_RE.sub(" ", response.text)
            body_lower = clean.lower()
            for indicator in ERROR_INDICATORS:
                if indicator in body_lower:
                    idx     = body_lower.index(indicator)
                    start   = max(0, idx - 80)
                    end     = min(len(clean), idx + 300)
                    snippet = clean[start:end]
                    return {
                        "url":       url,
                        "method":    method,
                        "status":    response.status_code,
                        "indicator": indicator,
                        "snippet":   snippet,
                    }

        except httpx.RequestError:
            pass
        return None

    async def _throttle(self) -> None:
        """
        Enforce settings.ERROR_MODULE_RATE_LIMIT (requests/second). This
        module fires many payload requests per crawled URL — unthrottled,
        that's a fast burst of attack-shaped requests against the target,
        risking a WAF/IDS trip or overloading a small site.
        """
        min_interval = 1.0 / max(settings.ERROR_MODULE_RATE_LIMIT, 1)
        last = getattr(self, "_last_request_ts", 0.0)
        wait = min_interval - (time.monotonic() - last)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_ts = time.monotonic()
