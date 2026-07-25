"""
modules/http_bypass.py
───────────────────────
Testcase: HTTP Bypass  (MEDIUM)

The host DOES run HTTPS on 443, but the same application is ALSO reachable
in cleartext on port 80 without being forced to HTTPS. Encryption exists but
isn't enforced, so an attacker can downgrade the connection (SSL-stripping /
MITM) even though a secure endpoint is available.

Decision logic (fires at most one MEDIUM finding):

    probe http://host/  (port 80, redirects NOT followed)
      ├─ connection refused ............... not vulnerable
      ├─ 3xx redirect to https:// ......... not vulnerable (HTTPS enforced)
      ├─ 4xx / 5xx ........................ not vulnerable (nothing served)
      └─ serves content in cleartext (2xx / non-https 3xx)
              ├─ HTTPS on 443 does NOT work → not vulnerable (→ Unencrypted Communication module)
              └─ HTTPS on 443 works ....... → HTTP Bypass (MEDIUM)
"""

import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding


class HttpBypassModule(BaseModule):
    name = "http_bypass"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        host     = self.scope.target_host
        http_url = f"http://{host}/"

        # Probe plain HTTP on port 80, without following redirects.
        try:
            async with httpx.AsyncClient(
                timeout=10, verify=False, follow_redirects=False
            ) as client:
                resp = await client.get(http_url)
        except httpx.RequestError:
            return findings   # port 80 closed → no downgrade path

        location = resp.headers.get("Location", "") or resp.headers.get("location", "")
        if resp.status_code in (301, 302, 307, 308) and location.lower().startswith("https://"):
            return findings   # HTTPS is enforced → not vulnerable

        if resp.status_code >= 400:
            return findings   # nothing usable served over HTTP

        # Cleartext content is served on port 80. This testcase only fires when
        # a secure HTTPS endpoint ALSO exists (otherwise it's Unencrypted
        # Communication, handled by that module).
        if not await self._https_available(host):
            return findings

        body_preview = resp.text[:300]
        findings.append(self.make_finding(
            title="HTTP Bypass",
            severity="high",
            description=(
                "The site is served over HTTPS on port 443, but the same "
                "application is also reachable in cleartext on port 80 without "
                "being redirected to HTTPS. An attacker can force a protocol "
                "downgrade (SSL stripping) and intercept traffic even though a "
                "secure endpoint is available."
            ),
            evidence=(
                f"HTTP URL accessible: {http_url}\n"
                f"Status code: {resp.status_code}\n"
                f"HTTPS (port 443) available: yes\n"
                f"No redirect to HTTPS on port 80.\n"
                f"Response preview: {body_preview}"
            ),
            affected_urls=[http_url],
            request_data=(
                f"GET / HTTP/1.1\n"
                f"Host: {host}\n"
                f"Cookie: <session_cookie>"
            ),
            response_data=f"HTTP {resp.status_code}\n{body_preview}",
            remediation=(
                "Redirect all port-80 (HTTP) traffic to HTTPS with a 301.\n"
                "Enable HSTS with preload to prevent SSL-stripping downgrades:\n"
                "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ),
        ))
        return findings

    async def _https_available(self, host: str) -> bool:
        """True if the host answers on HTTPS (port 443) at all."""
        try:
            async with httpx.AsyncClient(
                timeout=10, verify=False, follow_redirects=False
            ) as client:
                resp = await client.get(f"https://{host}/")
                return resp.status_code < 600
        except httpx.RequestError:
            return False
