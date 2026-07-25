"""
modules/res_splitting.py
─────────────────────────
Tests for HTTP Response Splitting vulnerabilities.

Attack: Injects CRLF sequences into user-controlled values that get
        reflected in response headers (e.g. redirect Location, Set-Cookie).
        A successful injection lets the attacker craft a fake HTTP response
        — enabling XSS, cache poisoning, and session fixation.

Payloads (CRLF injected via common redirect/return parameters):
  %0d%0aSet-Cookie:test=1             → inject a Set-Cookie header
  %0d%0aLocation:https://example.com  → inject a Location header

Detection (STRICT — real splits only, no reflection):
  A payload is vulnerable ONLY when the split actually happened at the HTTP
  layer, proven by the injected HEADER appearing as a real response header
  with the expected value (Set-Cookie:test=1, Location:https://example.com).
  Explicitly NOT flagged:
    - HTTP 400 (server rejected the CRLF — defended correctly)
    - the payload merely reflected inside an HTML/JSON body
    - the payload returned encoded / as plain text

Katana integration:
  Iterates ALL URLs discovered by Katana instead of only testing /.
  Stops at first confirmed vulnerable URL.
"""

import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding


# Common redirect/return parameters that get reflected in Location headers
REDIRECT_PARAMS = [
    "redirect",
    "url",
    "next",
    "return",
    "returnUrl",
    "return_url",
    "redirect_uri",
    "callback",
    "continue",
    "destination",
    "target",
]

# CRLF payloads. Each carries the concrete proof required to confirm a REAL
# split:
#   header/expect → an injected response header that must actually appear
#   header=None   → a body-split payload, proven only by a fresh injected body
CRLF_PAYLOADS = [
    {"value": "%0d%0aSet-Cookie:test=1",            "header": "set-cookie", "expect": "test=1"},
    {"value": "%0d%0aLocation:https://example.com", "header": "location",   "expect": "https://example.com"},
]


class ResSplittingModule(BaseModule):
    name = "res_splitting"

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
        Test a single URL for response splitting via redirect parameters.
        Returns a Finding if vulnerable, None otherwise.
        """
        for param in REDIRECT_PARAMS:
            for payload in CRLF_PAYLOADS:
                probe_url = self._build_probe_url(url, param, payload["value"])

                try:
                    response = await self._client.get(
                        probe_url,
                        follow_redirects=False,
                    )
                except httpx.RequestError:
                    continue

                vulnerable, detail = self._check_response(response, payload)
                if not vulnerable:
                    continue

                resp_headers = "\n".join(
                    f"{k}: {v}" for k, v in response.headers.items()
                )
                return self.make_finding(
                    title="HTTP Response Splitting",
                    severity="high",
                    description=(
                        "The application reflects user-controlled input "
                        "into HTTP response headers without sanitising CRLF sequences. "
                        "An attacker can inject fake HTTP headers and response bodies, "
                        "enabling XSS via header injection, cache poisoning, "
                        "and session fixation attacks."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Vulnerable parameter: {param}\n"
                        f"Payload: {payload['value']!r}\n"
                        f"Probe URL: {probe_url}\n\n"
                        f"{detail}\n\n"
                        f"Response headers:\n{resp_headers}"
                    ),
                    affected_urls=[url],
                    request_data=(
                        f"GET {probe_url} HTTP/1.1\n"
                        f"Host: {self.scope.target_host}\n"
                        f"Cookie: <session_cookie>"
                    ),
                    response_data=(
                        f"HTTP {response.status_code}\n"
                        f"{resp_headers}\n\n"
                        f"{response.text[:400]}"
                    ),
                    remediation=(
                        "Validate and sanitise all user-controlled input before "
                        "including it in response headers.\n"
                        "Strip or reject CR (\\r) and LF (\\n) characters.\n"
                        "Use allowlist validation for redirect URLs "
                        "(only allow known, relative paths).\n"
                        "Never reflect raw user input in Location, Set-Cookie, "
                        "or other response headers."
                    ),
                )

        return None

    @staticmethod
    def _build_probe_url(base_url: str, param: str, value: str) -> str:
        """
        Construct the probe URL with the CRLF payload in a redirect parameter.
        The payload is inserted LITERALLY (already percent-encoded) — it must
        NOT be re-encoded, or %0d%0a would become %250d%250a and the single-
        encoded test would silently become a double-encoded one.
        """
        sep = "&" if "?" in base_url else "?"
        return f"{base_url}{sep}{param}={value}"

    @staticmethod
    def _check_response(response: httpx.Response, payload: dict) -> tuple[bool, str]:
        """
        Confirm a REAL split (see module docstring). Returns (True, detail) only
        when the injected header/body actually materialised; (False, "") for
        reflection, encoding, or a 400 rejection.
        """
        # Server rejected the malformed request → defended correctly.
        if response.status_code == 400:
            return False, ""

        header = payload["header"]
        expect = payload["expect"].lower()

        if header:
            # The injected header must appear as a REAL, parsed response header.
            if hasattr(response.headers, "get_list"):
                values = response.headers.get_list(header)
            else:
                v = response.headers.get(header)
                values = [v] if v else []
            for v in values:
                if expect in v.lower():
                    return True, (
                        f"Injected '{header}' header is present in the response "
                        f"with value containing '{payload['expect']}' — the CRLF "
                        "split a new header into the response."
                    )
            return False, ""

        # Body-split payload: vulnerable only if the split produced a fresh
        # response body equal to the injected marker — NOT reflection inside a
        # larger HTML/JSON page.
        if response.text.strip() == payload["expect"]:
            return True, (
                "CRLF sequence split the response and produced a new body "
                f"containing only the injected marker '{payload['expect']}'."
            )
        return False, ""
