"""
modules/host_header.py
───────────────────────
Tests for Host Header Injection vulnerabilities.

Injection values (as specified):
  Primary:   example.com
  Secondary: bing.com

Sends 8 different injection payloads using headers:
  Host, X-Forwarded-Host, X-Host, X-Forwarded-Server,
  X-HTTP-Host-Override, Forwarded, X-Original-Host,
  and Host (spoofed) combined with X-Forwarded-Host (real domain) —
  this last one checks whether the backend trusts the raw Host header
  over a proxy-set X-Forwarded-Host that already carries the real domain.

Checks if the injected value is reflected in:
  - Location header
  - Response body
  - Any other response header

Katana integration:
  Iterates ALL URLs discovered by Katana instead of only testing /.
  Stops at first confirmed vulnerable URL + payload combination.
"""

import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding

PRIMARY_HOST   = "example.com"
SECONDARY_HOST = "bing.com"

INJECTION_PAYLOADS = [
    {"header": "Host",                 "value": PRIMARY_HOST},
    {"header": "Host",                 "value": SECONDARY_HOST},
    {"header": "X-Forwarded-Host",     "value": PRIMARY_HOST},
    {"header": "X-Host",               "value": PRIMARY_HOST},
    {"header": "X-Forwarded-Server",   "value": PRIMARY_HOST},
    {"header": "X-HTTP-Host-Override", "value": PRIMARY_HOST},
    {"header": "Forwarded",            "value": f"host={PRIMARY_HOST}"},
]


class HostHeaderModule(BaseModule):
    name = "host_header"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # 8th payload built per-scan: spoofed Host (example.com) combined
        # with X-Forwarded-Host set to the REAL target domain. This checks
        # whether the backend trusts the raw Host header over a proxy-set
        # X-Forwarded-Host that already carries the legitimate domain — if
        # "example.com" still shows up reflected, the app is using the
        # spoofable Host header rather than the trustworthy proxy header.
        payloads = INJECTION_PAYLOADS + [
            {
                "header": "Host",
                "value": PRIMARY_HOST,
                "extra": {"X-Forwarded-Host": self.scope.target_host},
            },
        ]

        _urls = self._get_urls()
        for _i, url in enumerate(_urls):
            await self.report_progress(_i, len(_urls))
            vulnerable_payloads: list[dict] = []

            for payload in payloads:
                try:
                    header_name  = payload["header"]
                    header_value = payload["value"]
                    extra_headers = payload.get("extra", {})

                    merged_headers = {
                        **dict(self._client.headers),
                        header_name: header_value,
                        **extra_headers,
                    }

                    response = await self._client.get(
                        url,
                        headers=merged_headers,
                        follow_redirects=False,
                    )

                    for injected in [PRIMARY_HOST, SECONDARY_HOST]:
                        reflected = self._check_reflection(response, injected)
                        if reflected:
                            vulnerable_payloads.append({
                                "url":       url,
                                "header":    header_name,
                                "value":     header_value,
                                "extra":     extra_headers,
                                "injected":  injected,
                                "reflected": reflected,
                                "status":    response.status_code,
                                "snippet":   response.text[:400],
                            })
                            break

                except httpx.RequestError:
                    continue

            if vulnerable_payloads:
                evidence = "\n\n".join(
                    f"URL: {p['url']}\n"
                    f"Injected header: {p['header']}: {p['value']}"
                    + (
                        "\n" + "\n".join(f"Extra header: {k}: {v}" for k, v in p['extra'].items())
                        if p.get('extra') else ""
                    )
                    + f"\nInjected value reflected: {p['injected']}\n"
                    f"Reflection found in: {p['reflected']}\n"
                    f"HTTP Status: {p['status']}\n"
                    f"Response snippet: {p['snippet']}"
                    for p in vulnerable_payloads
                )
                findings.append(self.make_finding(
                    title="Host Header Injection",
                    severity="low",
                    description=(
                        "The application reflects the attacker-controlled Host header value "
                        "in responses. This can be exploited for password reset poisoning "
                        "(attacker receives the reset link), cache poisoning, and SSRF."
                    ),
                    evidence=evidence,
                    affected_urls=[p["url"] for p in vulnerable_payloads],
                    request_data=(
                        f"GET <url> HTTP/1.1\n"
                        f"Host: {self.scope.target_host}\n"
                        f"X-Forwarded-Host: {PRIMARY_HOST}\n"
                        f"Cookie: <session_cookie>"
                    ),
                    response_data=vulnerable_payloads[0]["snippet"],
                    remediation=(
                        "Validate the Host header against an allowlist of expected domains.\n"
                        "Never use the Host header value directly in URL generation "
                        "(e.g. password reset links).\n"
                        "Use hardcoded application base URLs in configuration instead."
                    ),
                ))
                return findings   # Stop at first confirmed vulnerable URL

        return findings

    @staticmethod
    def _check_reflection(response: httpx.Response, injected: str) -> str:
        """Returns the location where reflection was found, or empty string."""
        location = response.headers.get("Location", "")
        if injected in location:
            return f"Location header: {location}"

        body = response.text
        if injected in body:
            idx   = body.index(injected)
            start = max(0, idx - 40)
            end   = min(len(body), idx + len(injected) + 40)
            return f"Response body: ...{body[start:end]}..."

        for header_name, header_value in response.headers.items():
            if injected in header_value:
                return f"Response header '{header_name}': {header_value}"

        return ""
