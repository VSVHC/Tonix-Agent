"""
modules/captcha.py
───────────────────
Checks if CAPTCHA is enabled on authentication-related pages.

Pages crawled (widened to match username_enum.py's path coverage):
  Login:    /login, /signin, /sign-in, /log-in, /user/login, /users/login,
            /account/login, /auth/login, /api/login, /session/new,
            /admin/login, /wp-login.php
  Reset:    /forgot-password, /forgot_password, /password/forgot,
            /reset-password, /password-reset, /account/forgot,
            /users/password/new
  Register: /register, /signup, /sign-up, /create-account, /account/register

  Plus every URL Katana tagged as a form page (crawl_result.forms) that
  isn't already covered above — catches auth pages at non-standard or
  client-side-routed paths that the fixed list would otherwise miss.

Rules:
  CAPTCHA present → NOT VULNERABLE (for that page)
  CAPTCHA absent  → VULNERABLE (for that page)

Each page is reported INDIVIDUALLY.

CAPTCHA detection checks:
  - Google reCAPTCHA (v2 / v3)
  - hCaptcha
  - Cloudflare Turnstile
  - Custom CAPTCHA image tags
  - Any challenge-response widget indicators
"""

import httpx
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from backend.modules.base_module import BaseModule
from backend.models import Finding

# Pages to check individually
CAPTCHA_PAGES = [
    # Login
    {"path": "/login",              "label": "Login"},
    {"path": "/signin",             "label": "Sign In"},
    {"path": "/sign-in",            "label": "Sign In (alternate)"},
    {"path": "/log-in",             "label": "Log In"},
    {"path": "/user/login",         "label": "Login (user path)"},
    {"path": "/users/login",        "label": "Login (users path)"},
    {"path": "/account/login",      "label": "Account Login"},
    {"path": "/auth/login",         "label": "Auth Login"},
    {"path": "/api/login",          "label": "API Login"},
    {"path": "/session/new",        "label": "Session New (Rails-style login)"},
    {"path": "/admin/login",        "label": "Admin Login"},
    {"path": "/wp-login.php",       "label": "WordPress Login"},
    # Password reset
    {"path": "/forgot",             "label": "Forgot Password (bare)"},
    {"path": "/reset",              "label": "Reset Password (bare)"},
    {"path": "/recover",            "label": "Recover Account (bare)"},
    {"path": "/forgot-password",    "label": "Forgot Password"},
    {"path": "/forgot_password",    "label": "Forgot Password (underscore)"},
    {"path": "/password/forgot",    "label": "Password Forgot"},
    {"path": "/reset-password",     "label": "Reset Password"},
    {"path": "/password-reset",     "label": "Password Reset (alternate)"},
    {"path": "/account/forgot",     "label": "Account Forgot Password"},
    {"path": "/users/password/new", "label": "Users Password New (Rails-style reset)"},
    # Registration
    {"path": "/register",           "label": "Register"},
    {"path": "/signup",             "label": "Sign Up"},
    {"path": "/sign-up",            "label": "Sign Up (alternate)"},
    {"path": "/create-account",     "label": "Create Account"},
    {"path": "/account/register",   "label": "Account Register"},
]

# CAPTCHA detection signatures
CAPTCHA_SIGNATURES = [
    # Google reCAPTCHA v2 / v3
    {"name": "Google reCAPTCHA",     "check": lambda html, soup: (
        "recaptcha" in html.lower()
        or bool(soup.find(attrs={"class": lambda c: c and "recaptcha" in str(c).lower()}))
        or bool(soup.find("div", {"data-sitekey": True}))
        or "grecaptcha" in html.lower()
        or "google.com/recaptcha" in html.lower()
    )},
    # hCaptcha
    {"name": "hCaptcha",             "check": lambda html, soup: (
        "hcaptcha" in html.lower()
        or bool(soup.find(attrs={"class": lambda c: c and "h-captcha" in str(c).lower()}))
        or "hcaptcha.com" in html.lower()
    )},
    # Cloudflare Turnstile
    {"name": "Cloudflare Turnstile", "check": lambda html, soup: (
        "cf-turnstile" in html.lower()
        or "challenges.cloudflare.com" in html.lower()
        or bool(soup.find(attrs={"class": lambda c: c and "cf-turnstile" in str(c).lower()}))
    )},
    # Generic CAPTCHA image
    {"name": "CAPTCHA Image",        "check": lambda html, soup: (
        bool(soup.find("img", {"src": lambda s: s and "captcha" in s.lower()}))
        or bool(soup.find("input", {"name": lambda n: n and "captcha" in n.lower()}))
    )},
    # Arkose Labs / FunCaptcha
    {"name": "FunCaptcha/Arkose",    "check": lambda html, soup: (
        "funcaptcha" in html.lower()
        or "arkoselabs" in html.lower()
    )},
    # Generic data-captcha attribute
    {"name": "Generic CAPTCHA widget","check": lambda html, soup: (
        bool(soup.find(attrs={"data-captcha": True}))
        or bool(soup.find(attrs={"data-recaptcha": True}))
        or bool(soup.find(attrs={"id": lambda i: i and "captcha" in i.lower()}))
    )},
]


class CaptchaModule(BaseModule):
    name = "captcha"

    def _candidates(self) -> list[dict]:
        """
        Fixed guessed pages (with human-readable labels) + any
        Katana-discovered form URLs not already covered by the fixed list.
        """
        fixed = [{"url": self.scope.build_url(p["path"]), "label": p["label"]} for p in CAPTCHA_PAGES]
        fixed_urls = {c["url"] for c in fixed}

        cr = self.scope.crawl_result
        discovered = []
        if cr and cr.forms:
            for url in cr.forms:
                if url in fixed_urls:
                    continue
                label = f"Discovered Form ({urlparse(url).path or url})"
                discovered.append({"url": url, "label": label})

        return fixed + discovered

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        checked_pages: set[str] = set()   # Avoid duplicate final URLs

        for page in self._candidates():
            url   = page["url"]
            label = page["label"]

            try:
                response = await self.get(path="", raw_url=url)

                # Skip pages that do not exist or redirect away
                if response.status_code not in (200,):
                    continue

                # Skip if we've already seen this final URL (after redirects)
                final_url = str(response.url)
                if final_url in checked_pages:
                    continue
                checked_pages.add(final_url)

                html = response.text
                soup = BeautifulSoup(html, "html.parser")

                captcha_found = self._detect_captcha(html, soup)

                if captcha_found:
                    # CAPTCHA is present — NOT VULNERABLE
                    findings.append(self.make_finding(
                        title=f"CAPTCHA Present on {label} Page — Not Vulnerable",
                        severity="info",
                        description=(
                            f"The {label} page ({url}) has CAPTCHA protection enabled. "
                            f"Detected: {captcha_found}. "
                            "This page is protected against automated bot attacks."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"HTTP Status: {response.status_code}\n"
                            f"CAPTCHA detected: {captcha_found}\n"
                            f"Result: NOT VULNERABLE"
                        ),
                        affected_urls=[url],
                        request_data=(
                            f"GET {url} HTTP/1.1\n"
                            f"Host: {self.scope.target_host}\n"
                            f"Cookie: <session_cookie>"
                        ),
                        response_data=f"CAPTCHA widget detected: {captcha_found}",
                        remediation="No action required — CAPTCHA is correctly implemented.",
                    ))
                else:
                    # CAPTCHA is absent — VULNERABLE
                    findings.append(self.make_finding(
                        title="CAPTCHA Not Enabled",
                        severity="info",
                        description=(
                            f"The {label} page ({url}) does not have CAPTCHA protection. "
                            "Without CAPTCHA, the page is susceptible to automated brute-force "
                            "attacks, credential stuffing, and mass registration/spam."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"HTTP Status: {response.status_code}\n"
                            f"CAPTCHA detected: None\n"
                            f"Result: VULNERABLE\n\n"
                            f"Checked for: Google reCAPTCHA, hCaptcha, Cloudflare Turnstile, "
                            f"FunCaptcha, CAPTCHA image, generic CAPTCHA widgets."
                        ),
                        affected_urls=[url],
                        request_data=(
                            f"GET {url} HTTP/1.1\n"
                            f"Host: {self.scope.target_host}\n"
                            f"Cookie: <session_cookie>"
                        ),
                        response_data=(
                            f"No CAPTCHA widget found in page source.\n"
                            f"Page snippet:\n{html[:400]}"
                        ),
                        remediation=(
                            "Implement CAPTCHA on this page to prevent automated attacks.\n"
                            "Recommended options:\n"
                            "  Google reCAPTCHA v3: https://www.google.com/recaptcha\n"
                            "  hCaptcha:            https://www.hcaptcha.com\n"
                            "  Cloudflare Turnstile: https://developers.cloudflare.com/turnstile\n"
                            "Also consider rate limiting and account lockout as complementary controls."
                        ),
                    ))

            except httpx.RequestError:
                continue

        return findings

    @staticmethod
    def _detect_captcha(html: str, soup: BeautifulSoup) -> str:
        """
        Checks all CAPTCHA signatures against the page HTML and parsed DOM.
        Returns the name of the detected CAPTCHA, or empty string if none found.
        """
        for sig in CAPTCHA_SIGNATURES:
            try:
                if sig["check"](html, soup):
                    return sig["name"]
            except Exception:
                continue
        return ""
