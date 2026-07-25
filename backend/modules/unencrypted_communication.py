"""
modules/unencrypted_communication.py
─────────────────────────────────────
Testcase: Unencrypted Communication  (HIGH)

The host is reachable over plain HTTP (port 80) and serves content instead
of redirecting to HTTPS, AND the host has no working HTTPS service. The
application has no transport encryption at all — every request/response
(credentials, session tokens) travels in cleartext and can be read or
modified by any attacker on the network (MITM).

Decision logic (fires at most one HIGH finding):

    probe http://host/  (port 80, redirects NOT followed)
      ├─ connection refused ............... not vulnerable
      ├─ 3xx redirect to https:// ......... not vulnerable (HTTPS enforced)
      ├─ 4xx / 5xx ........................ not vulnerable (nothing served)
      └─ serves content in cleartext (2xx / non-https 3xx)
              ├─ HTTPS on 443 works ....... not vulnerable  (→ HTTP Bypass module)
              └─ HTTPS on 443 does NOT work → Unencrypted Communication (HIGH)
"""

import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding


class UnencryptedCommunicationModule(BaseModule):
    name = "unencrypted_communication"

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
            return findings   # port 80 closed → nothing served in cleartext

        location = resp.headers.get("Location", "") or resp.headers.get("location", "")
        if resp.status_code in (301, 302, 307, 308) and location.lower().startswith("https://"):
            return findings   # HTTPS is enforced → not vulnerable

        if resp.status_code >= 400:
            return findings   # nothing usable served over HTTP

        # Cleartext content is served on port 80. This testcase only fires when
        # there is NO secure endpoint at all (otherwise it's an HTTP Bypass).
        if await self._https_available(host):
            return findings

        body_preview = resp.text[:300]
        findings.append(self.make_finding(
            title="Unencrypted Communication",
            severity="high",
            description=(
                "The application is served over plain HTTP and has no working "
                "HTTPS service. All traffic — including credentials and session "
                "tokens — is transmitted in cleartext and can be read or modified "
                "by any attacker positioned on the network (MITM)."
            ),
            evidence=(
                f"HTTP URL accessible: {http_url}\n"
                f"Status code: {resp.status_code}\n"
                f"HTTPS (port 443) available: no\n"
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
                "Deploy a valid TLS certificate and serve the application over HTTPS.\n"
                "Redirect all HTTP (port 80) traffic to HTTPS with a 301.\n"
                "Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains"
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
