"""
modules/clickjacking.py
────────────────────────
Checks if the application is vulnerable to clickjacking attacks.

Rule (as specified):
  Vulnerable whenever X-Frame-Options is ABSENT. This covers both:
    - both headers absent, and
    - X-Frame-Options absent while Content-Security-Policy IS present.
  If X-Frame-Options is present, the page is NOT vulnerable — regardless
  of whether CSP is present. Severity: LOW.

  Only checks for PRESENCE of headers — not their values.

Katana integration:
  Iterates ALL URLs discovered by Katana instead of only testing /.
  One aggregated finding is raised listing all affected URLs.
"""

import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding


class ClickjackingModule(BaseModule):
    name = "clickjacking"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        affected_urls: list[str] = []
        evidence_blocks: list[str] = []

        _urls = self._get_urls()
        for _i, url in enumerate(_urls):
            await self.report_progress(_i, len(_urls))
            try:
                response = await self.get(path="", raw_url=url)
                headers  = response.headers

                xfo_present = headers.get("X-Frame-Options") is not None
                csp_present = headers.get("Content-Security-Policy") is not None

                # Vulnerable whenever X-Frame-Options is absent — CSP being
                # present is NOT treated as sufficient framing protection here.
                if not xfo_present:
                    detail = (
                        f"X-Frame-Options: NOT PRESENT\n"
                        f"Content-Security-Policy: {'PRESENT' if csp_present else 'NOT PRESENT'}\n"
                        "  (X-Frame-Options is absent — page can be framed)"
                    )

                    affected_urls.append(url)
                    evidence_blocks.append(
                        f"URL: {url}\n"
                        f"HTTP Status: {response.status_code}\n"
                        f"{detail}"
                    )

            except httpx.RequestError:
                continue

        if affected_urls:
            resp_headers_sample = ""
            try:
                sample_resp = await self.get(path="", raw_url=affected_urls[0])
                resp_headers_sample = "\n".join(
                    f"{k}: {v}" for k, v in sample_resp.headers.items()
                )
            except httpx.RequestError:
                pass

            findings.append(self.make_finding(
                title="Clickjacking Protection Not Implemented",
                severity="low",
                description=(
                    "The application does not send an X-Frame-Options header on "
                    f"{len(affected_urls)} URL(s) discovered during crawling. "
                    "An attacker can embed these pages in a hidden iframe on a malicious site "
                    "and trick users into unknowingly clicking on UI elements, leading to "
                    "unauthorized actions such as account changes, transactions, or data submission."
                ),
                evidence=(
                    f"Affected URLs ({len(affected_urls)} total):\n\n"
                    + "\n\n".join(evidence_blocks[:10])   # cap evidence at 10 samples
                    + (f"\n\n...and {len(affected_urls) - 10} more." if len(affected_urls) > 10 else "")
                    + f"\n\nSample response headers (first affected URL):\n{resp_headers_sample}"
                ),
                affected_urls=affected_urls,
                request_data=(
                    f"GET <url> HTTP/1.1\n"
                    f"Host: {self.scope.target_host}\n"
                    f"Cookie: <session_cookie>"
                ),
                response_data=resp_headers_sample,
                remediation=(
                    "Add X-Frame-Options: DENY to all responses to prevent iframe embedding.\n"
                    "Alternatively use: Content-Security-Policy: frame-ancestors 'none'\n"
                    "For login and sensitive pages, DENY is the recommended value."
                ),
            ))

        return findings
