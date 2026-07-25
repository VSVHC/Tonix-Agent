"""
modules/autocomplete.py
────────────────────────
Checks for insecure autocomplete on the password input field.

Rule (as specified):
  VULNERABLE:
    autocomplete="on"
    autocomplete="current-password"

  NOT VULNERABLE:
    autocomplete="off"
    autocomplete=""            (empty)
    autocomplete attribute absent (missing)

  Severity: informational.

Scope:
  - Only checks the password input field (type="password")
  - Fetches login, signin pages
  - Checks only <input type="password"> fields

Candidate pages:
  - A fixed list of common login path guesses (works even without a crawl)
  - Every URL Katana tagged as a form page (crawl_result.forms) — covers
    login pages at non-standard, custom, or client-side-routed paths that
    the fixed guess list alone would miss entirely.
"""

import httpx
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from backend.modules.base_module import BaseModule
from backend.models import Finding

LOGIN_PATHS = [
    "/login",
    "/signin",
    "/sign-in",
    "/log-in",
    "/user/login",
    "/users/login",
    "/account/login",
    "/auth/login",
    "/wp-login.php",
    "/admin/login",
]

# Only login/sign-in pages carry a password field worth checking, so
# crawl-discovered forms are filtered to these before being tested.
LOGIN_KEYWORDS = ("login", "signin", "sign-in", "sign_in", "log-in", "log_in",
                  "session", "auth")

VULNERABLE_AUTOCOMPLETE_VALUES = {"on", "current-password"}


class AutocompleteModule(BaseModule):
    name = "autocomplete"

    def _candidates(self) -> list[str]:
        """
        Fixed guessed login paths + any Katana-discovered form URLs, deduped.
        Discovered URLs are already absolute and already scope-verified by
        the crawler (crawl_result.forms only ever contains verified,
        in-scope URLs).
        """
        fixed = [self.scope.build_url(p) for p in LOGIN_PATHS]
        cr = self.scope.crawl_result
        discovered = [
            u for u in (cr.forms if cr and cr.forms else [])
            if any(k in urlparse(u).path.lower() for k in LOGIN_KEYWORDS)
        ]
        return list(dict.fromkeys(fixed + discovered))

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for url in self._candidates():
            try:
                response = await self.get(path="", raw_url=url)
                if response.status_code not in (200,):
                    continue

                soup   = BeautifulSoup(response.text, "html.parser")
                result = self._check_password_autocomplete(soup)

                if result["vulnerable"]:
                    findings.append(self.make_finding(
                        title="Insecure Autocomplete on Password Field",
                        severity="info",
                        description=(
                            "The password input field allows browser autocomplete, "
                            "which can expose stored credentials to unauthorized users "
                            "on shared or public devices. The browser will offer to save "
                            "and auto-fill the password."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"HTTP Status: {response.status_code}\n\n"
                            f"Password field HTML:\n{result['field_html']}\n\n"
                            f"autocomplete attribute value: {result['autocomplete_value']}\n"
                            f"Reason: {result['reason']}"
                        ),
                        affected_urls=[url],
                        request_data=(
                            f"GET {url} HTTP/1.1\n"
                            f"Host: {self.scope.target_host}\n"
                            f"Cookie: <session_cookie>"
                        ),
                        response_data=result["field_html"],
                        remediation=(
                            "Add autocomplete=\"off\" to the password input field.\n"
                            "Example: <input type=\"password\" name=\"password\" autocomplete=\"off\">\n"
                            "This prevents the browser from caching and auto-filling passwords."
                        ),
                    ))
                    return findings   # One confirmed finding is enough

            except httpx.RequestError:
                continue

        return findings

    @staticmethod
    def _check_password_autocomplete(soup: BeautifulSoup) -> dict:
        """
        Inspect all password input fields on the page.

        VULNERABLE only if a field explicitly sets autocomplete="on" or
        autocomplete="current-password". A missing attribute, an empty value,
        "off", or any other value is treated as NOT vulnerable.

        Returns a dict with vulnerable, field_html, autocomplete_value, reason.
        """
        for inp in soup.find_all("input", {"type": "password"}):
            field_html = str(inp)[:300]

            # .get() returns None if the attribute is absent.
            autocomplete_attr = inp.get("autocomplete")

            # Missing attribute → treated as safe (not vulnerable).
            if autocomplete_attr is None:
                continue

            autocomplete_val = autocomplete_attr.lower().strip()

            if autocomplete_val in VULNERABLE_AUTOCOMPLETE_VALUES:
                # on / current-password = VULNERABLE
                return {
                    "vulnerable":       True,
                    "field_html":       field_html,
                    "autocomplete_value": autocomplete_val,
                    "reason": (
                        f"autocomplete='{autocomplete_val}' explicitly enables "
                        f"browser password saving and auto-fill."
                    ),
                }

            # "off", "" (empty), or any other value → safe; keep scanning
            # any remaining password fields on the page.

        # No password field explicitly set to on/current-password.
        return {
            "vulnerable":       False,
            "field_html":       "",
            "autocomplete_value": "N/A",
            "reason": "No password field with autocomplete on/current-password found.",
        }
