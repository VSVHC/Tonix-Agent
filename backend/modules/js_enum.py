"""
modules/js_enum.py
───────────────────
Enumerates and analyses JavaScript files for sensitive information.

Rules (as specified):
  - Fetch homepage, extract all in-scope <script src> URLs (max 30)
  - Scan each JS file for 30+ sensitive patterns
  - False positives (placeholder, example, etc.) → SKIP
  - Internal API endpoints → reported as SEPARATE finding from secrets
  - Severity: Critical for AWS keys, passwords, JWTs
              High for API secrets
              Medium for others
"""

import re
import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding

# ── Secret patterns ──────────────────────────────────────
SECRET_PATTERNS = [
    (r"AIza[0-9A-Za-z\-_]{35}",                                    "Google API Key",              "high"),
    (r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",                  "Firebase Cloud Messaging Key","high"),
    (r"['\"]?api[_\-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "Generic API Key",    "high"),
    (r"['\"]?api[_\-]?secret['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]","API Secret",       "high"),
    (r"['\"]?access[_\-]?token['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]","Access Token",  "high"),
    (r"['\"]?auth[_\-]?token['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]", "Auth Token",    "high"),
    (r"['\"]?secret[_\-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-\.!@#$%]{8,})['\"]","Secret Key", "high"),
    (r"['\"]?client[_\-]?secret['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{10,})['\"]","OAuth Client Secret","high"),
    # AWS
    (r"AKIA[0-9A-Z]{16}",                                          "AWS Access Key ID",           "critical"),
    (r"['\"]?aws[_\-]?secret[_\-]?access[_\-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+]{40})['\"]","AWS Secret Access Key","critical"),
    (r"s3\.amazonaws\.com/[A-Za-z0-9_\-\.]+",                     "Amazon S3 Bucket URL",        "medium"),
    (r"[A-Za-z0-9_\-]+\.s3\.amazonaws\.com",                      "Amazon S3 Bucket Domain",     "medium"),
    # Firebase
    (r"https://[a-z0-9\-]+\.firebaseio\.com",                      "Firebase Database URL",       "high"),
    (r"https://[a-z0-9\-]+\.firebasestorage\.app",                 "Firebase Storage URL",        "high"),
    (r"['\"]?firebase[_\-]?api[_\-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{35,})['\"]","Firebase API Key","critical"),
    # Passwords
    (r"['\"]?password['\"]?\s*[:=]\s*['\"]([^'\"]{4,})['\"]",     "Hardcoded Password",          "critical"),
    (r"['\"]?passwd['\"]?\s*[:=]\s*['\"]([^'\"]{4,})['\"]",       "Hardcoded Password (passwd)", "critical"),
    (r"['\"]?db[_\-]?pass(word)?['\"]?\s*[:=]\s*['\"]([^'\"]{4,})['\"]","Database Password",     "critical"),
    # Usernames
    (r"['\"]?username['\"]?\s*[:=]\s*['\"]([^'\"]{3,})['\"]",     "Hardcoded Username",          "medium"),
    (r"['\"]?db[_\-]?user['\"]?\s*[:=]\s*['\"]([^'\"]{3,})['\"]", "Database Username",           "medium"),
    # JWT
    (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+","JWT Token",                   "critical"),
    # Private IPs
    (r"(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)","Private IP Address","medium"),
    # Keys
    (r"['\"]?private[_\-]?key['\"]?\s*[:=]\s*['\"]([^'\"]{10,})['\"]","Private Key",             "critical"),
    (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",               "PEM Private Key",             "critical"),
    # Third-party tokens
    (r"sk_live_[0-9a-zA-Z]{24,}",                                  "Stripe Live Secret Key",      "critical"),
    (r"pk_live_[0-9a-zA-Z]{24,}",                                  "Stripe Live Publishable Key", "high"),
    (r"AC[a-z0-9]{32}",                                            "Twilio Account SID",           "medium"),
    (r"SK[0-9a-fA-F]{32}",                                         "Twilio Auth Token",            "high"),
    (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",              "SendGrid API Key",             "critical"),
    (r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",          "Slack Token",                  "critical"),
    (r"ghp_[A-Za-z0-9]{36}",                                       "GitHub Personal Access Token", "critical"),
    (r"gho_[A-Za-z0-9]{36}",                                       "GitHub OAuth Token",           "critical"),
]

# ── Internal API endpoint pattern (reported separately) ──
API_ENDPOINT_PATTERN = re.compile(
    r"""['"](/api/[a-zA-Z0-9_\-/\.?=&]{3,})['"]""",
    re.IGNORECASE,
)

COMPILED_SECRET_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), label, severity)
    for pattern, label, severity in SECRET_PATTERNS
]

FALSE_POSITIVE_VALUES = {
    "your-api-key", "your-secret", "enter-key-here", "xxx",
    "placeholder", "example", "changeme", "undefined", "null",
    "true", "false", "test", "sample", "dummy", "xxxxxxxx",
}

# Labels whose regex matches on a field NAME ("password"/"username") rather
# than a fixed, secret-shaped prefix (like "AKIA..." or "sk_live_..."). These
# fire constantly on ordinary UI copy — placeholders, labels, validation
# text — that happens to sit next to those words. Matches for these labels
# get extra scrutiny in _extract_secrets() below.
HUMAN_TEXT_PRONE_LABELS = {
    "Hardcoded Password", "Hardcoded Password (passwd)", "Database Password",
    "Hardcoded Username", "Database Username",
}

# Common non-secret phrases that share the same field names. Real hardcoded
# credentials are opaque tokens — they don't read like sentences.
UI_COPY_PHRASES = {
    "password", "username", "email", "required", "optional",
    "enter password", "your password", "confirm password", "new password",
    "current password", "old password", "enter your password",
    "enter username", "your username", "enter your username",
    "type here", "field is required", "this field is required",
}

MAX_JS_FILES = 30

# JS chunks/bundles whose URL suggests app-specific config or entry code —
# scanned first. Modern SPAs can have 100+ code-split chunks; without this,
# MAX_JS_FILES silently truncates in whatever order Katana happened to list
# files, which is usually not the order that matters for secret-hunting.
_HIGH_PRIORITY_HINTS = ("config", "env", "settings", "main", "app", "index", "bundle")
# Large shared/library bundles — least likely to contain app-specific
# secrets, scanned last within the cap.
_LOW_PRIORITY_HINTS = ("vendor", "polyfill", "runtime", "chunk-vendors")


# CVSS per impact tier (company scheme). Maps each secret pattern's declared
# band → the (severity, score, vector) actually reported:
#   critical → live cloud / privileged credentials
#   high     → API key / token / secret
#   medium   → internal identifier / URL only → reported as Low
_CVSS_BY_TIER = {
    "critical": ("critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "high":     ("high",     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "medium":   ("low",      3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
}
# Internal API endpoints (URL-only disclosure) → Low tier.
_ENDPOINT_CVSS = _CVSS_BY_TIER["medium"]


class JsEnumModule(BaseModule):
    name = "js_enum"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        js_urls = self._prioritize(await self._collect_js_urls())
        if not js_urls:
            return findings

        all_secrets: list[dict]   = []
        all_endpoints: list[dict] = []

        for js_url in js_urls[:MAX_JS_FILES]:
            try:
                response = await self.get(raw_url=js_url, path="")
                if response.status_code != 200:
                    continue

                content = response.text
                all_secrets.extend(self._extract_secrets(content, js_url))
                all_endpoints.extend(self._extract_endpoints(content, js_url))

            except httpx.RequestError:
                continue

        # ── Findings: Secrets (grouped by type) ──────────
        by_type: dict[str, list] = {}
        for s in all_secrets:
            by_type.setdefault(s["label"], []).append(s)

        for label, instances in by_type.items():
            severity, cvss_score, cvss_vector = _CVSS_BY_TIER[instances[0]["severity"]]
            evidence = "\n\n".join(
                f"File: {inst['file']}\n"
                f"Type: {inst['label']}\n"
                f"Match: {inst['match'][:200]}\n"
                f"Context: ...{inst['context']}..."
                for inst in instances[:5]
            )
            affected = list({inst["file"] for inst in instances})

            findings.append(self.make_finding(
                title=f"Sensitive Information in JavaScript: {label}",
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                description=(
                    f"The application's JavaScript files contain what appears to be "
                    f"a {label}. Sensitive information hardcoded in client-side JavaScript "
                    f"is accessible to any user who views the page source."
                ),
                evidence=evidence,
                affected_urls=affected,
                request_data=(
                    f"GET {affected[0]} HTTP/1.1\n"
                    f"Host: {self.scope.target_host}\n"
                    f"Cookie: <session_cookie>"
                ),
                response_data=f"Found {len(instances)} instance(s) of {label}",
                remediation=(
                    f"Remove all hardcoded {label} values from client-side JavaScript.\n"
                    "Use server-side environment variables for sensitive configuration.\n"
                    "Rotate any exposed credentials or API keys immediately.\n"
                    "Implement backend proxy endpoints for third-party API calls."
                ),
            ))

        # ── Findings: Internal API Endpoints (separate) ──
        if all_endpoints:
            endpoint_list = list({e["endpoint"] for e in all_endpoints})
            endpoint_lines = "\n".join(
                f"  {ep['endpoint']}  (found in: {ep['file']})"
                for ep in all_endpoints[:30]
            )
            findings.append(self.make_finding(
                title="Internal API Endpoints Exposed in JavaScript",
                severity=_ENDPOINT_CVSS[0],
                cvss_score=_ENDPOINT_CVSS[1],
                cvss_vector=_ENDPOINT_CVSS[2],
                description=(
                    "Internal API endpoint paths were found hardcoded in client-side "
                    "JavaScript files. These paths provide attackers with a map of "
                    "the application's API surface for targeted testing."
                ),
                evidence=(
                    f"Found {len(endpoint_list)} unique internal API endpoint(s):\n\n"
                    f"{endpoint_lines}"
                ),
                affected_urls=list({e["file"] for e in all_endpoints}),
                request_data=(
                    f"GET {all_endpoints[0]['file']} HTTP/1.1\n"
                    f"Host: {self.scope.target_host}\n"
                    f"Cookie: <session_cookie>"
                ),
                response_data="\n".join(endpoint_list[:20]),
                remediation=(
                    "Avoid hardcoding API endpoint paths in client-side JavaScript.\n"
                    "Use relative paths where possible.\n"
                    "Ensure all internal API endpoints enforce authentication and authorization."
                ),
            ))

        return findings

    async def _collect_js_urls(self) -> list[str]:
        """
        Return JS file URLs discovered by Katana during the crawl phase.

        Reads directly from crawl_result.js_files which contains all .js
        URLs found by Katana across every page (including JS-rendered pages
        via -jc). No homepage scraping fallback — if Katana did not run or
        found no JS files, js_enum skips entirely.
        """
        cr = self.scope.crawl_result
        if not cr or not cr.js_files:
            return []
        return cr.js_files

    @staticmethod
    def _prioritize(js_urls: list[str]) -> list[str]:
        """Sort so config/app-shaped bundles are scanned before vendor bundles."""
        def sort_key(url: str) -> tuple[int, int]:
            low = url.lower()
            if any(h in low for h in _HIGH_PRIORITY_HINTS):
                tier = 0
            elif any(h in low for h in _LOW_PRIORITY_HINTS):
                tier = 2
            else:
                tier = 1
            return (tier, len(low))
        return sorted(js_urls, key=sort_key)

    def _extract_secrets(self, content: str, file_url: str) -> list[dict]:
        """Scan JS content for sensitive patterns, skipping false positives."""
        results = []
        for pattern, label, severity in COMPILED_SECRET_PATTERNS:
            for match in pattern.finditer(content):
                matched_value = match.group(0)

                # Skip obvious false positives
                if any(fp in matched_value.lower() for fp in FALSE_POSITIVE_VALUES):
                    continue
                if len(matched_value.strip()) < 6:
                    continue

                # Extra scrutiny for password/username-shaped patterns: they
                # match on the field NAME, not a fixed secret-shaped prefix,
                # so they need to actually look like an opaque token rather
                # than ordinary UI copy before being trusted.
                if label in HUMAN_TEXT_PRONE_LABELS:
                    # The actual secret value is always the LAST capture
                    # group — some patterns (e.g. "Database Password") have
                    # an earlier optional group ("(word)?") that isn't it.
                    groups   = [g for g in match.groups() if g is not None]
                    captured = groups[-1] if groups else matched_value
                    if " " in captured.strip():
                        continue   # real secrets don't read like sentences
                    if captured.strip().lower() in UI_COPY_PHRASES:
                        continue

                # Get surrounding context (1 line)
                pos        = match.start()
                line_start = content.rfind("\n", 0, pos) + 1
                line_end   = content.find("\n", pos)
                context    = content[line_start:line_end if line_end != -1 else pos + 100].strip()

                results.append({
                    "label":    label,
                    "severity": severity,
                    "match":    matched_value,
                    "context":  context[:200],
                    "file":     file_url,
                })
        return results

    @staticmethod
    def _extract_endpoints(content: str, file_url: str) -> list[dict]:
        """Extract internal API endpoint paths from JS content."""
        results = []
        for match in API_ENDPOINT_PATTERN.finditer(content):
            endpoint = match.group(1)
            # Skip very short or obviously non-API paths
            if len(endpoint) < 5 or endpoint in ("/api/", "/api"):
                continue
            results.append({"endpoint": endpoint, "file": file_url})
        return results
