"""
modules/username_enum.py
─────────────────────────
Detects username / account enumeration on auth flows.

Detection strategy (two engines, best-first):

  1. DIFFERENTIAL (reliable, primary) — the "oracle" approach.
     For a form, submit TWO identities and compare the responses:
       A = a random, definitely-nonexistent account
       B = a candidate that may exist
     If the site responds CONSISTENTLY DIFFERENTLY for the two (status code,
     normalised body length, or normalised body text) — repeated across a
     couple of rounds for stability — then the form leaks account existence,
     regardless of the exact wording. This catches leaks the phrase list
     would miss and does NOT depend on guessing error strings.

     The candidate B must be an account that actually EXISTS to be meaningful:
       - Login form: only reliable with a KNOWN-good account (a random and a
         guessed account both just get "wrong password"), so the login
         differential runs ONLY when a known account is provided
         (ScanRequest.known_account_email or settings.USERNAME_ENUM_KNOWN_ACCOUNT).
       - Reset / signup forms: run the differential when a known account is
         provided; otherwise fall back to engine 2.

  2. PHRASE (fallback / booster) — the original message-based check.
     If the response text matches a known enumeration phrase ("user not
     found", "password is incorrect for…") and NOT a generic phrase
     ("invalid username or password"), it's flagged. Always evaluated on the
     responses already fetched, so it costs no extra requests.

Test credentials (fixed): email testaswd123@gmail.com, password apples@9121.

Pages crawled: login, forgot password, signup — plus any URL Katana tagged
as a form page (crawl_result.forms), keyword-categorised into those buckets.
"""

import re
import secrets
import httpx
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

from backend.config import settings
from backend.modules.base_module import BaseModule
from backend.models import Finding

TEST_EMAIL    = "testaswd123@gmail.com"
TEST_PASSWORD = "apples@9121"

# How many times each identity is submitted when comparing, to be sure a
# difference is stable and not just random page noise.
STABILITY_ROUNDS = 2

# Cap on how many form-bearing pages we'll fully test per bucket, so a large
# site doesn't explode the request count (each tested form costs a few POSTs).
MAX_FORMS_PER_BUCKET = 3

LOGIN_PATHS = [
    "/login",
    "/signin",
    "/sign-in",
    "/log-in",
    "/user/login",
    "/users/login",
    "/account/login",
    "/auth/login",
    "/api/login",
    "/session/new",
    "/admin/login",
    "/wp-login.php",
]

RESET_PATHS = [
    "/forgot",
    "/reset",
    "/recover",
    "/forgot-password",
    "/forgot_password",
    "/password/forgot",
    "/reset-password",
    "/password-reset",
    "/account/forgot",
    "/users/password/new",
]

SIGNUP_PATHS = [
    "/register",
    "/signup",
    "/sign-up",
    "/create-account",
    "/account/register",
]

# Keywords used to route Katana-discovered form URLs into the buckets.
RESET_KEYWORDS  = ("forgot", "reset", "recover")
SIGNUP_KEYWORDS = ("register", "signup", "sign-up", "sign_up", "create-account", "create_account")
LOGIN_KEYWORDS  = ("login", "log-in", "log_in", "signin", "sign-in", "sign_in", "session")

# Field-name candidates per bucket.
LOGIN_ID_FIELDS   = ["username", "email", "user", "login", "identifier", "email_or_username"]
LOGIN_PW_FIELDS   = ["password", "pass", "passwd", "secret"]
RESET_ID_FIELDS   = ["email", "username", "user", "login", "email_address"]
SIGNUP_ID_FIELDS  = ["email", "username", "user", "email_address"]
SIGNUP_PW_FIELDS  = ["password", "pass", "passwd", "password_confirmation",
                     "password_confirm", "confirm_password"]

# Generic (safe) messages — do NOT indicate enumeration.
GENERIC_MESSAGES = [
    r"invalid\s+(username|email|credentials?)",
    r"incorrect\s+(username|email|password|credentials?)",
    r"login\s+failed",
    r"authentication\s+failed",
    r"(username|email)\s+or\s+password\s+(is\s+)?(incorrect|invalid|wrong)",
    r"wrong\s+(username|email)\s+or\s+password",
    r"could\s+not\s+log\s+you\s+in",
    r"sign.in\s+failed",
    r"the\s+information\s+you\s+entered\s+(is\s+)?incorrect",
    r"please\s+check\s+your\s+(email|username)\s+and\s+password",
]

# Enumeration indicators — THESE reveal account existence.
ENUMERATION_INDICATORS = [
    r"(user|account|email).{0,30}(not\s+found|does\s+not\s+exist|not\s+registered|no\s+account)",
    r"no\s+(user|account)\s+(found|exists)\s+(with\s+)?(that|this|the)",
    r"(email|username).{0,20}(not\s+exist|unregistered|not\s+in\s+our)",
    r"we\s+(couldn.t|could\s+not|can.t)\s+find\s+(a\s+)?(user|account|email)",
    r"(password|pin).{0,20}(is\s+)?(incorrect|wrong|invalid).{0,30}(username|email)",
    r"password\s+is\s+(incorrect|wrong)",    # Reveals the username IS valid
    r"incorrect\s+password\s+for",
    r"this\s+email\s+(address\s+)?is\s+not\s+registered",
    r"that\s+(email|username)\s+(address\s+)?isn.t\s+associated",
    r"(create\s+an\s+account|sign\s+up).{0,40}(first|instead)",
    r"account\s+with\s+(this|that)\s+(email|username)\s+(not\s+found|doesn.t\s+exist)",
    r"already\s+(registered|taken|in\s+use|exists)",    # signup: email exists
    r"(email|username)\s+already\s+(registered|taken|in\s+use|exists)",
]

COMPILED_GENERIC    = [re.compile(p, re.IGNORECASE) for p in GENERIC_MESSAGES]
COMPILED_INDICATORS = [re.compile(p, re.IGNORECASE) for p in ENUMERATION_INDICATORS]

# Dynamic content stripped before comparing two responses, so CSRF tokens /
# nonces / timestamps don't look like a real difference.
_TOKEN_RE = re.compile(r"[0-9a-f]{12,}", re.IGNORECASE)
_DIGIT_RE = re.compile(r"\d+")
_WS_RE    = re.compile(r"\s+")


class UsernameEnumModule(BaseModule):
    name = "username_enum"

    # ─────────────────────────────────────────────────────
    #  Config
    # ─────────────────────────────────────────────────────

    def _known_account(self) -> str | None:
        """The known-good account, from the scan request or global config."""
        per_scan = getattr(self.scope, "known_account_email", None)
        return (per_scan or settings.USERNAME_ENUM_KNOWN_ACCOUNT or "").strip() or None

    @staticmethod
    def _random_email() -> str:
        """An address overwhelmingly unlikely to exist on any target."""
        return f"pentest_nouser_{secrets.token_hex(6)}@example.com"

    # ─────────────────────────────────────────────────────
    #  Katana form categorisation
    # ─────────────────────────────────────────────────────

    def _discovered_by_category(self) -> tuple[list[str], list[str], list[str]]:
        cr = self.scope.crawl_result
        if not cr or not cr.forms:
            return [], [], []

        login, reset, signup = [], [], []
        for url in cr.forms:
            p = urlparse(url).path.lower()
            if any(k in p for k in RESET_KEYWORDS):
                reset.append(url)
            elif any(k in p for k in SIGNUP_KEYWORDS):
                signup.append(url)
            elif any(k in p for k in LOGIN_KEYWORDS):
                login.append(url)
        return login, reset, signup

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        disc_login, disc_reset, disc_signup = self._discovered_by_category()
        known = self._known_account()

        await self._test_bucket(
            findings, "Login", LOGIN_PATHS, disc_login,
            LOGIN_ID_FIELDS, LOGIN_PW_FIELDS,
            # Login differential only makes sense with a known-good account.
            allow_differential=known is not None, known=known,
        )
        await self._test_bucket(
            findings, "Forgot Password", RESET_PATHS, disc_reset,
            RESET_ID_FIELDS, [],
            allow_differential=known is not None, known=known,
        )
        await self._test_bucket(
            findings, "Signup", SIGNUP_PATHS, disc_signup,
            SIGNUP_ID_FIELDS, SIGNUP_PW_FIELDS,
            allow_differential=known is not None, known=known,
        )
        return findings

    # ─────────────────────────────────────────────────────
    #  Per-bucket testing
    # ─────────────────────────────────────────────────────

    async def _test_bucket(
        self,
        findings: list,
        label: str,
        fixed_paths: list[str],
        discovered: list[str],
        id_fields: list[str],
        pw_fields: list[str],
        allow_differential: bool,
        known: str | None,
    ) -> None:
        candidates = list(dict.fromkeys(
            [self.scope.build_url(p) for p in fixed_paths] + list(discovered)
        ))
        forms_tested = 0

        for url in candidates:
            if forms_tested >= MAX_FORMS_PER_BUCKET:
                return
            try:
                page = await self.get(path="", raw_url=url)
                if page.status_code != 200:
                    continue

                fields, action = self._extract_form_fields(page.text, id_fields)
                if not fields:
                    continue

                forms_tested += 1

                # Submit to where the form actually posts (its action), not the
                # page URL — many forms post to a separate handler endpoint.
                post_url = urljoin(url, action) if action else url

                verdict = await self._evaluate_form(
                    post_url, fields, id_fields, pw_fields, allow_differential, known
                )
                if verdict:
                    findings.append(self._build_finding(label, url, verdict))
                    return   # one confirmed finding per bucket is enough

            except httpx.RequestError:
                continue

    async def _evaluate_form(
        self,
        url: str,
        fields: dict,
        id_fields: list[str],
        pw_fields: list[str],
        allow_differential: bool,
        known: str | None,
    ) -> dict | None:
        """
        Returns a verdict dict {method, reason} if the form leaks account
        existence, else None.
        """
        # ── Engine 1: differential (needs a known-good account) ──
        if allow_differential and known:
            rand = self._random_email()
            resp_rand = await self._submit_rounds(url, fields, id_fields, pw_fields, rand)
            resp_known = await self._submit_rounds(url, fields, id_fields, pw_fields, known)

            differ, detail = self._consistently_differ(resp_rand, rand, resp_known, known)
            if differ:
                return {"method": "differential", "reason": detail}

            # Booster: phrase check on the known-account response.
            if resp_known:
                phrase = self._find_enumeration_indicator(resp_known[-1].text)
                if phrase:
                    return {"method": "message", "reason": f"Enumeration message: '{phrase}'"}
            return None

        # ── Engine 2: phrase fallback (no known account) ──
        resp = await self._submit(url, fields, id_fields, pw_fields, TEST_EMAIL)
        if resp is None:
            return None
        phrase = self._find_enumeration_indicator(resp.text)
        if phrase:
            return {"method": "message", "reason": f"Enumeration message: '{phrase}'"}
        return None

    # ─────────────────────────────────────────────────────
    #  Submission helpers
    # ─────────────────────────────────────────────────────

    async def _submit(
        self, url: str, fields: dict, id_fields: list[str],
        pw_fields: list[str], identity: str,
    ) -> httpx.Response | None:
        payload = dict(fields)
        for f in id_fields:
            if f in payload:
                payload[f] = identity
        for f in pw_fields:
            if f in payload:
                payload[f] = TEST_PASSWORD
        try:
            return await self.post(path="", data=payload, raw_url=url)
        except httpx.RequestError:
            return None

    async def _submit_rounds(
        self, url: str, fields: dict, id_fields: list[str],
        pw_fields: list[str], identity: str,
    ) -> list[httpx.Response]:
        out: list[httpx.Response] = []
        for _ in range(STABILITY_ROUNDS):
            r = await self._submit(url, fields, id_fields, pw_fields, identity)
            if r is not None:
                out.append(r)
        return out

    # ─────────────────────────────────────────────────────
    #  Response comparison
    # ─────────────────────────────────────────────────────

    def _consistently_differ(
        self,
        resp_a: list[httpx.Response], id_a: str,
        resp_b: list[httpx.Response], id_b: str,
    ) -> tuple[bool, str]:
        """
        True only if BOTH sets of responses are internally stable AND the two
        sets differ from each other — the signature of an enumeration oracle.
        """
        if not resp_a or not resp_b:
            return False, ""

        sig_a = {self._signature(r, id_a) for r in resp_a}
        sig_b = {self._signature(r, id_b) for r in resp_b}

        # Each identity must respond consistently to itself (no random noise).
        if len(sig_a) != 1 or len(sig_b) != 1:
            return False, ""

        a = next(iter(sig_a))
        b = next(iter(sig_b))
        if a == b:
            return False, ""

        parts = []
        if a[0] != b[0]:
            parts.append(f"status {a[0]} vs {b[0]}")
        if a[1] != b[1]:
            parts.append(f"body length ~{a[1] * 64} vs ~{b[1] * 64} bytes")
        if a[2] != b[2]:
            parts.append("response text differs")
        detail = (
            f"Nonexistent account and known account produced consistently "
            f"different responses ({', '.join(parts)}) across "
            f"{STABILITY_ROUNDS} round(s) — the form leaks account existence."
        )
        return True, detail

    def _signature(self, resp: httpx.Response, identity: str) -> tuple:
        """(status, length-bucket, normalised-text) — the submitted identity
        and dynamic tokens are stripped so they don't create fake differences."""
        body = self._normalize(resp.text, identity)
        return (resp.status_code, len(body) // 64, body[:2000])

    @staticmethod
    def _normalize(text: str, identity: str) -> str:
        t = text.lower()
        if identity:
            t = t.replace(identity.lower(), "x")
            local = identity.split("@")[0].lower()
            if local:
                t = t.replace(local, "x")
        t = _TOKEN_RE.sub("x", t)
        t = _DIGIT_RE.sub("n", t)
        t = _WS_RE.sub(" ", t)
        return t.strip()

    # ─────────────────────────────────────────────────────
    #  Finding builder + shared helpers
    # ─────────────────────────────────────────────────────

    def _build_finding(self, label: str, url: str, verdict: dict) -> Finding:
        method = "response differential" if verdict["method"] == "differential" else "error message"
        return self.make_finding(
            title=f"Username Enumeration via {label} Form",
            severity="low",
            description=(
                f"The {label.lower()} form reveals whether an account exists. "
                f"Detected by {method}. An attacker can use this to enumerate "
                "valid usernames or email addresses for targeted attacks such as "
                "credential stuffing and phishing."
            ),
            evidence=(
                f"URL: {url}\n"
                f"Detection method: {method}\n"
                f"{verdict['reason']}\n"
                f"Test password used: {TEST_PASSWORD}"
            ),
            affected_urls=[url],
            request_data=(
                f"POST {url} HTTP/1.1\n"
                f"Host: {self.scope.target_host}\n"
                f"Content-Type: application/x-www-form-urlencoded\n"
                f"Cookie: <session_cookie>\n\n"
                f"<identity>=<account>&password=<password>"
            ),
            response_data=verdict["reason"],
            remediation=(
                "Return an identical, generic message for every failed attempt "
                "(e.g. 'Invalid username or password.'), with the same status "
                "code and response size.\n"
                "For password reset and signup, always respond with a neutral "
                "message ('If this email is registered, you will receive a link.').\n"
                "Add consistent response timing to prevent timing-based enumeration."
            ),
        )

    @staticmethod
    def _find_enumeration_indicator(body: str) -> str:
        """
        Returns a matched enumeration phrase if the body reveals account
        existence. Returns "" if the message is generic (safe).
        """
        for pattern in COMPILED_GENERIC:
            if pattern.search(body):
                return ""
        for pattern in COMPILED_INDICATORS:
            match = pattern.search(body)
            if match:
                return match.group(0)[:120]
        return ""

    @staticmethod
    def _extract_form_fields(
        html: str, id_fields: list[str] | None = None
    ) -> tuple[dict, str | None]:
        """Extract ``(fields, action)`` for the page's auth form.

        Prefers the form that actually contains one of ``id_fields`` (the
        username/email input for this bucket), so a search or newsletter form
        higher up the page doesn't get picked instead. Falls back to the first
        non-empty form when none match.

        ``action`` is the form's raw ``action`` attribute (or None if absent) so
        the caller can POST to where the form submits, not the page URL.
        """
        soup     = BeautifulSoup(html, "html.parser")
        id_set   = set(id_fields or [])
        fallback = None                        # (fields, action)
        for form in soup.find_all("form"):
            fields = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name and inp.get("type", "").lower() not in ("submit", "button", "image", "reset"):
                    fields[name.lower()] = inp.get("value", "")
            if not fields:
                continue
            action = form.get("action") or None
            if id_set & fields.keys():
                return fields, action          # form has the identity field → this is the one
            if fallback is None:
                fallback = (fields, action)
        return fallback if fallback else ({}, None)
