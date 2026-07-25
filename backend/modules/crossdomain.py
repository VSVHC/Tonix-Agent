"""
modules/crossdomain.py
───────────────────────
Checks for insecure Adobe Flash cross-domain policy file.

File checked:
  - /crossdomain.xml  (Adobe Flash cross-domain policy only)

Verification approach — CONTENT-based, not status-code-based:
  A 200 status alone is not trusted (SPA catch-alls / soft-404 pages can
  return 200 with the homepage instead of a real 404). The response body
  must actually contain the mandatory <cross-domain-policy> root tag —
  every real Flash policy file has this, no exceptions — before it's
  treated as a genuine hit.

Severity rules:
  Critical : domain="*" wildcard found
  High     : permissive access rules exist (allow-access-from / allow-http-request-headers-from)
  Medium   : file simply exists (information disclosure)

Redirect handling:
  Request follows redirects normally (e.g. a site-wide http -> https
  upgrade on the SAME path still counts as a genuine hit). But if it
  redirects to a DIFFERENT path (e.g. a catch-all redirect to the
  homepage), it is treated as not present.
"""

import re
import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding

WILDCARD_RE   = re.compile(r'domain\s*=\s*["\*]\*["\*]?', re.IGNORECASE)
PERMISSIVE_RE = re.compile(
    r'<allow-access-from|<allow-http-request-headers-from', re.IGNORECASE
)


class CrossDomainModule(BaseModule):
    name = "crossdomain"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        try:
            # Follow redirects normally — only skip if the redirect lands
            # on a DIFFERENT path (e.g. a catch-all redirect to the homepage).
            response = await self.get("/crossdomain.xml")

            if self.redirected_elsewhere(response, "/crossdomain.xml"):
                return findings

            if response.status_code != 200:
                return findings

            body = response.text

            # Content verification — every real Flash policy file has this
            # mandatory root tag. If it's missing, what we got back is the
            # homepage/login/error page in disguise, not a real policy file.
            if "<cross-domain-policy" not in body.lower():
                return findings

            url  = self.scope.build_url("/crossdomain.xml")

            is_wildcard   = bool(WILDCARD_RE.search(body))
            is_permissive = bool(PERMISSIVE_RE.search(body))

            if is_wildcard:
                severity    = "critical"
                vuln_detail = (
                    "The policy contains a wildcard (*) domain rule, allowing ANY origin "
                    "to make cross-domain requests. This completely bypasses the Same-Origin Policy."
                )
            elif is_permissive:
                severity    = "high"
                vuln_detail = (
                    "The policy file exists and contains permissive access rules. "
                    "Review all allowed domains to ensure only trusted origins are permitted."
                )
            else:
                severity    = "medium"
                vuln_detail = (
                    "The policy file exists and is publicly accessible. "
                    "Even restrictive policy files disclose the cross-domain access configuration."
                )

            findings.append(self.make_finding(
                title="Insecure Cross-Domain Policy File Found (crossdomain.xml)",
                severity=severity,
                description=(
                    "The Adobe Flash cross-domain policy file was found at /crossdomain.xml. "
                    + vuln_detail
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"HTTP Status: {response.status_code}\n"
                    f"Wildcard domain='*' detected: {is_wildcard}\n"
                    f"Permissive rules detected: {is_permissive}\n\n"
                    f"File contents:\n{body[:800]}"
                ),
                affected_urls=[url],
                request_data=(
                    f"GET /crossdomain.xml HTTP/1.1\n"
                    f"Host: {self.scope.target_host}\n"
                    f"Cookie: <session_cookie>"
                ),
                response_data=body[:800],
                remediation=(
                    "Remove /crossdomain.xml — Flash and Silverlight are end-of-life technologies.\n"
                    "If absolutely required, replace wildcard (*) with specific trusted domains.\n"
                    "Prefer modern CORS headers (Access-Control-Allow-Origin) over legacy policy files."
                ),
            ))

        except httpx.RequestError:
            pass

        return findings
