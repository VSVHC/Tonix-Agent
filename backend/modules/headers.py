"""
modules/headers.py
──────────────────
Audits HTTP response headers for missing security headers.

Rule: Check ONLY if each header is present or absent.
      Do NOT check header values — presence alone determines result.

Headers checked (severity in parentheses):
  Strict-Transport-Security   (low)
  X-Content-Type-Options      (info)
  Content-Security-Policy     (info)
  Referrer-Policy             (info)
  Permissions-Policy          (info)

Note: Server header is excluded from this module (handled by web_server.py).
      X-Frame-Options is excluded here — its absence is reported by the
      clickjacking module instead, to avoid double-reporting the same header.
"""

import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding

SECURITY_HEADERS = [
    {
        "header":      "Strict-Transport-Security",
        "title":       "Missing Strict-Transport-Security (HSTS) Header",
        "severity":    "low",
        "description": (
            "The Strict-Transport-Security header is absent. Without HSTS, browsers "
            "may access the site over HTTP, making it vulnerable to SSL stripping attacks "
            "where an attacker downgrades the connection from HTTPS to HTTP."
        ),
        "remediation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
            "This enforces HTTPS connections and prevents SSL stripping."
        ),
    },
    {
        "header":      "X-Content-Type-Options",
        "title":       "Missing X-Content-Type-Options Header",
        "severity":    "info",
        "description": (
            "The X-Content-Type-Options header is absent. Without this header, browsers may "
            "MIME-sniff the content type of responses, potentially executing malicious content "
            "as a different type than intended (e.g. treating a plain text file as JavaScript)."
        ),
        "remediation": (
            "Add: X-Content-Type-Options: nosniff\n"
            "This prevents browsers from MIME-type sniffing."
        ),
    },
    {
        "header":      "Content-Security-Policy",
        "title":       "Missing Content-Security-Policy (CSP) Header",
        "severity":    "info",
        "description": (
            "The Content-Security-Policy header is absent. Without CSP, the application has no "
            "control over what resources can be loaded, significantly increasing the risk of "
            "Cross-Site Scripting (XSS) and data injection attacks."
        ),
        "remediation": (
            "Add a Content-Security-Policy header with appropriate directives.\n"
            "Example: Content-Security-Policy: default-src 'self'; script-src 'self'\n"
            "Avoid using 'unsafe-inline' or 'unsafe-eval' in the policy."
        ),
    },
    {
        "header":      "Referrer-Policy",
        "title":       "Missing Referrer-Policy Header",
        "severity":    "info",
        "description": (
            "The Referrer-Policy header is absent. Without this header, browsers may send "
            "the full URL (including query parameters) as the Referer header to third-party "
            "sites, potentially leaking sensitive information such as session tokens or "
            "search queries."
        ),
        "remediation": (
            "Add: Referrer-Policy: strict-origin-when-cross-origin\n"
            "Or: Referrer-Policy: no-referrer for maximum privacy."
        ),
    },
    {
        "header":      "Permissions-Policy",
        "title":       "Missing Permissions-Policy Header",
        "severity":    "info",
        "description": (
            "The Permissions-Policy header is absent. Without this header, the application "
            "does not restrict access to browser features such as camera, microphone, "
            "geolocation, and payment, which may be abused by injected third-party scripts."
        ),
        "remediation": (
            "Add: Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()\n"
            "Restrict all features that the application does not use."
        ),
    },
]


class HeadersModule(BaseModule):
    name = "headers"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        try:
            response = await self.get("/")
            headers  = response.headers

            req_repr = (
                f"GET / HTTP/1.1\n"
                f"Host: {self.scope.target_host}\n"
                f"Cookie: <session_cookie>"
            )
            resp_headers = "\n".join(f"{k}: {v}" for k, v in headers.items())

            for check in SECURITY_HEADERS:
                header_name  = check["header"]
                header_value = headers.get(header_name)

                # Only check presence — absent means vulnerable
                if header_value is None:
                    findings.append(self.make_finding(
                        title=check["title"],
                        severity=check["severity"],
                        description=check["description"],
                        evidence=(
                            f"Header: {header_name}\n"
                            f"Value:  NOT PRESENT\n\n"
                            f"All response headers received:\n{resp_headers}"
                        ),
                        affected_urls=[self.scope.base_url + "/"],
                        request_data=req_repr,
                        response_data=resp_headers,
                        remediation=check["remediation"],
                    ))

        except httpx.RequestError:
            pass

        return findings
