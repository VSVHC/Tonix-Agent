"""
modules/req_splitting.py
─────────────────────────
Tests for HTTP Request Splitting / Header Injection via the URL.

Payloads (a second request line injected via CRLF):
  %0d%0aGET%20/test%20HTTP/1.1     → CRLF-prefixed second request line
  %250d%250aGET%20/test%20HTTP/1.1 → double-encoded CRLF (tests a decoder
                                     that unwraps %25 before parsing)
Each payload is injected in two locations: a query parameter and a trailing
URL path segment.

Detection (STRICT — confirmed header injection only):
  True request splitting (a smuggled second request actually being processed)
  cannot be confirmed with a standard HTTP client — httpx controls the wire
  framing and returns a single parsed response, so "second request executed"
  is not observable here. We therefore flag ONLY the reliably-detectable
  signal: the injected request-line tokens surfacing in the REAL response
  HEADER block, which can only happen if the CRLF broke out into the header
  section (a genuine split), AND the status is not a rejection.

  Explicitly NOT flagged:
    - HTTP 400 (server rejected the CRLF) or 404
    - the payload merely reflected in the response BODY (HTML/JSON)
    - the payload returned encoded / as plain text

Katana integration:
  Iterates ALL URLs discovered by Katana instead of only testing /.
  Stops at first confirmed vulnerable URL.
"""

import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding


# Second-request-line payloads (already percent-encoded — inserted literally).
PAYLOADS = [
    "%0d%0aGET%20/test%20HTTP/1.1",
    "%250d%250aGET%20/test%20HTTP/1.1",
]

# Locations to inject each payload into.
LOCATIONS = ["query", "path"]

# Tokens that, appearing TOGETHER in a response header, indicate the injected
# request line broke into the header block (a real split). A safe server never
# emits a response header derived from "/test ... HTTP/1.1".
_SPLIT_TOKENS = ("/test", "http/1.1")


class ReqSplittingModule(BaseModule):
    name = "req_splitting"

    @staticmethod
    def _inject(url: str, location: str, value: str) -> str:
        """
        Place the payload in the URL.
          location="query" → append as a new query parameter
                              (handles an existing query string)
          location="path"  → append as a new trailing path segment
        The payload is inserted LITERALLY (already percent-encoded).
        """
        if location == "query":
            separator = "&" if "?" in url else "?"
            return f"{url}{separator}rsplit_test={value}"
        else:  # path
            return f"{url.rstrip('/')}/{value}"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        _urls = self._get_urls()
        for _i, url in enumerate(_urls):
            await self.report_progress(_i, len(_urls))
            hit = await self._test_url(url)
            if hit:
                findings.append(hit)
                return findings   # Stop at first confirmed finding

        return findings

    async def _test_url(self, url: str) -> Finding | None:
        """
        Test a single URL with each request-splitting payload in both the query
        and path. Returns a Finding only on confirmed header injection.
        """
        for value in PAYLOADS:
            for location in LOCATIONS:
                injected_url = self._inject(url, location, value)

                try:
                    response = await self._client.get(injected_url)
                except httpx.RequestError:
                    continue

                vulnerable, detail = self._check_response(response)
                if not vulnerable:
                    continue

                resp_headers = "\n".join(
                    f"{k}: {v}" for k, v in response.headers.items()
                )
                return self.make_finding(
                    title="HTTP Request Splitting / Header Injection via URL",
                    severity="high",
                    description=(
                        "A CRLF-injected request line broke out into the response "
                        f"header block when injected via a URL {location}. An attacker "
                        "can use CRLF (\\r\\n) sequences in URLs to inject arbitrary "
                        "response headers, enabling cache poisoning, session fixation, "
                        "and request/response splitting attacks against proxies, CDNs, "
                        "and browsers."
                    ),
                    evidence=(
                        f"URL: {injected_url}\n"
                        f"Injection location: URL {location}\n"
                        f"Injected value: {value}\n\n"
                        f"{detail}\n\n"
                        f"Response headers:\n{resp_headers}\n\n"
                        f"Response body snippet:\n{response.text[:400]}"
                    ),
                    affected_urls=[injected_url],
                    request_data=(
                        f"GET {injected_url} HTTP/1.1\n"
                        f"Host: {self.scope.target_host}\n"
                        f"Cookie: <session_cookie>"
                    ),
                    response_data=(
                        f"HTTP {response.status_code}\n"
                        f"{resp_headers}\n\n"
                        f"{response.text[:400]}"
                    ),
                    remediation=(
                        "Reject or strip CR (\\r) and LF (\\n) characters from all URL "
                        "path segments and query parameters before using them to build "
                        "response headers.\n"
                        "Use an HTTP library that validates and normalises headers.\n"
                        "Never reflect raw, unescaped user input into response headers "
                        "or HTML bodies.\n"
                        "Configure CDN/proxy to use the same HTTP parsing rules as the backend."
                    ),
                )

        return None

    @staticmethod
    def _check_response(response: httpx.Response) -> tuple[bool, str]:
        """
        Confirm header injection only (see module docstring). Vulnerable only
        when the injected request-line tokens appear in a REAL response header
        and the status is not a rejection. Body reflection is NOT flagged.
        """
        if response.status_code in (400, 404):
            return False, ""

        for name, value in response.headers.items():
            blob = f"{name}: {value}".lower()
            if all(tok in blob for tok in _SPLIT_TOKENS):
                return True, (
                    f"Injected request-line tokens surfaced in a response header: "
                    f"'{name}: {value}' — the CRLF broke into the header block."
                )
        return False, ""
