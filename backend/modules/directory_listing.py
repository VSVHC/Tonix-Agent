"""
modules/directory_listing.py
─────────────────────────────
Checks for open directory listing on common web paths.

Rules (as specified):
  - Focus probe path: /uploads/ (primary)
  - Also probes other common paths
  - HTTP 200 with directory listing signatures → VULNERABLE
  - HTTP 200 with a normal webpage (no listing) → NOT VULNERABLE (report as such)
  - HTTP 403 Forbidden → NOT VULNERABLE (report as such — directory exists but protected)
  - High severity: sensitive directories (backup, logs, config, admin)
  - Medium severity: other directories

Listing signatures:
  "Index of /"
  "Parent Directory"
  "Directory listing for"
"""

import re
import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding

DIRECTORIES_TO_PROBE = [
    "/uploads/",
    "/upload/",
    "/files/",
    "/static/",
    "/assets/",
    "/media/",
    "/images/",
    "/backup/",
    "/backups/",
    "/bak/",
    "/logs/",
    "/log/",
    "/temp/",
    "/tmp/",
    "/cache/",
    "/data/",
    "/admin/",
    "/private/",
    "/config/",
    "/conf/",
    "/docs/",
    "/downloads/",
    "/export/",
    "/exports/",
    "/src/",
    "/vendor/",
    "/node_modules/",
]

SENSITIVE_DIRS = {
    "/backup/", "/backups/", "/bak/",
    "/logs/", "/log/",
    "/config/", "/conf/",
    "/admin/", "/private/",
    "/data/", "/export/", "/exports/",
}

LISTING_PATTERNS = [
    re.compile(r"Index of /",              re.IGNORECASE),
    re.compile(r"Directory listing for",   re.IGNORECASE),
    re.compile(r"<title>Index of",         re.IGNORECASE),
    re.compile(r"\[To Parent Directory\]", re.IGNORECASE),
    re.compile(r"Parent Directory</a>",    re.IGNORECASE),
    re.compile(r"<h1>Index of /",          re.IGNORECASE),
]


class DirectoryListingModule(BaseModule):
    name = "directory_listing"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for directory in DIRECTORIES_TO_PROBE:
            try:
                response = await self.get(directory)
                status   = response.status_code
                url      = self.scope.build_url(directory)

                if status == 200:
                    pattern_hit = self._detect_listing(response.text)

                    if pattern_hit:
                        # Directory listing is exposed — VULNERABLE
                        # ponytail: fixed Low per company scheme; SENSITIVE_DIRS no
                        # longer changes severity (kept only for evidence context).
                        severity = "low"
                        findings.append(self.make_finding(
                            title=f"Open Directory Listing: {directory}",
                            severity=severity,
                            description=(
                                f"The web server returns a browsable directory index for {directory}. "
                                "This exposes the file structure and allows attackers to enumerate "
                                "and download files including backups, logs, config, and source code."
                            ),
                            evidence=(
                                f"URL: {url}\n"
                                f"HTTP Status: {status}\n"
                                f"Detected pattern: {pattern_hit}\n\n"
                                f"Response snippet:\n{response.text[:600]}"
                            ),
                            affected_urls=[url],
                            request_data=(
                                f"GET {directory} HTTP/1.1\n"
                                f"Host: {self.scope.target_host}\n"
                                f"Cookie: <session_cookie>"
                            ),
                            response_data=response.text[:600],
                            remediation=(
                                "Disable directory listing on the web server.\n"
                                "Nginx:  autoindex off;  (in server/location block)\n"
                                "Apache: Options -Indexes  (in .htaccess or httpd.conf)\n"
                                "IIS:    Disable 'Directory Browsing' in site properties.\n"
                                "Ensure all directories have an appropriate index file."
                            ),
                        ))
                    else:
                        # HTTP 200 but normal page — NOT VULNERABLE
                        findings.append(self.make_finding(
                            title=f"Directory Probe: {directory} — Not Vulnerable (Normal Page)",
                            severity="info",
                            description=(
                                f"{directory} returned HTTP 200 but serves a normal webpage, "
                                "not a directory listing. No file enumeration is possible."
                            ),
                            evidence=(
                                f"URL: {url}\n"
                                f"HTTP Status: {status}\n"
                                f"No directory listing signatures detected.\n"
                                f"Response snippet:\n{response.text[:200]}"
                            ),
                            affected_urls=[url],
                            request_data=(
                                f"GET {directory} HTTP/1.1\n"
                                f"Host: {self.scope.target_host}\n"
                                f"Cookie: <session_cookie>"
                            ),
                            response_data=response.text[:200],
                            remediation="No action required.",
                        ))

                elif status == 403:
                    # 403 Forbidden — directory exists but listing is blocked — NOT VULNERABLE
                    findings.append(self.make_finding(
                        title=f"Directory Probe: {directory} — Not Vulnerable (403 Forbidden)",
                        severity="info",
                        description=(
                            f"{directory} returned HTTP 403 Forbidden. "
                            "The directory exists but directory listing is blocked by the server. "
                            "This is the expected secure behaviour."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"HTTP Status: 403 Forbidden\n"
                            f"Directory listing is blocked."
                        ),
                        affected_urls=[url],
                        request_data=(
                            f"GET {directory} HTTP/1.1\n"
                            f"Host: {self.scope.target_host}\n"
                            f"Cookie: <session_cookie>"
                        ),
                        response_data=f"HTTP 403 Forbidden",
                        remediation="No action required — directory listing is correctly blocked.",
                    ))

            except httpx.RequestError:
                continue

        return findings

    @staticmethod
    def _detect_listing(body: str) -> str:
        """Returns matched pattern if directory listing detected, else empty string."""
        for pattern in LISTING_PATTERNS:
            if pattern.search(body):
                return pattern.pattern
        return ""
