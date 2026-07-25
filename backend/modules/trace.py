"""
modules/trace.py
─────────────────
Checks if HTTP TRACE method is enabled on the server.

Rule:
  Sends TRACE to each discovered URL.
  Vulnerable ONLY if the server returns HTTP 200 AND the response body
  actually contains proof of an echo (the unique probe header value, or
  the request line starting with "TRACE"). A bare 200 alone is not
  trusted — SPA catch-all / soft-404 routing (see katana_crawler.py's
  soft-404 detection) can return 200 with the normal app shell for
  almost any method or path, which previously would have been
  misread as XST-vulnerable with no supporting evidence at all.
  Severity: LOW (as specified)

Attack: Cross-Site Tracing (XST) — steal cookies/auth tokens
        even when HttpOnly flag is set.

Katana integration:
  Iterates ALL URLs discovered by Katana instead of only testing /.
  Stops at first confirmed hit (one TRACE finding per scan is sufficient).
"""

import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding


class TraceModule(BaseModule):
    name = "trace"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        _urls = self._get_urls()
        for _i, url in enumerate(_urls):
            await self.report_progress(_i, len(_urls))
            try:
                req_headers = {
                    "X-PentestAgent-Probe": "trace-test",
                    "Host": self.scope.target_host,
                    "Cookie": "<session_cookie>",
                }
                response = await self.request("TRACE", "/", headers=req_headers, raw_url=url)

                is_vulnerable = False
                detail        = ""

                if response.status_code == 200:
                    body = response.text
                    # Require actual proof the server echoed the request
                    # back — the unique probe header value, or the
                    # response starting with the TRACE request line — not
                    # just any HTTP 200. A generic 200 with no echo is
                    # almost always catch-all/soft-404 routing, not XST.
                    echoed_probe  = "X-PENTESTAGENT-PROBE" in body.upper()
                    echoed_method = body.strip().upper().startswith("TRACE")

                    if echoed_probe or echoed_method:
                        is_vulnerable = True
                        reason = "probe header" if echoed_probe else "request line"
                        detail = (
                            f"Server returned HTTP 200 and echoed the request back "
                            f"({reason} found verbatim in the response body), "
                            f"confirming TRACE method is enabled and reflects raw request data.\n\n"
                            f"Response body snippet:\n{response.text[:400]}"
                        )

                if is_vulnerable:
                    resp_headers = "\n".join(
                        f"{k}: {v}" for k, v in response.headers.items()
                    )
                    findings.append(self.make_finding(
                        title="HTTP TRACE Method Enabled",
                        severity="low",
                        description=(
                            "The server has the HTTP TRACE method enabled. "
                            "This can be exploited via Cross-Site Tracing (XST) attacks "
                            "to steal sensitive headers including session cookies and "
                            "authorization tokens, even when HttpOnly flags are set."
                        ),
                        evidence=(
                            f"Confirmed on URL: {url}\n\n"
                            f"{detail}"
                        ),
                        affected_urls=[url],
                        request_data=(
                            f"TRACE {url} HTTP/1.1\n"
                            f"Host: {self.scope.target_host}\n"
                            f"X-PentestAgent-Probe: trace-test\n"
                            f"Cookie: <session_cookie>"
                        ),
                        response_data=(
                            f"HTTP/1.1 {response.status_code}\n"
                            f"{resp_headers}\n\n"
                            f"{response.text[:500]}"
                        ),
                        remediation=(
                            "Disable the TRACE method on the web server.\n"
                            "Apache: Add 'TraceEnable Off' to httpd.conf\n"
                            "Nginx:  if ($request_method = TRACE) { return 405; }"
                        ),
                    ))
                    return findings   # Stop at first confirmed hit

            except httpx.RequestError:
                continue

        return findings
