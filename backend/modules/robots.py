"""
modules/robots.py
──────────────────
Checks for information disclosure via robots.txt.

Paths checked:
  /robots.txt   (standard)
  /robot.txt    (common typo variant)

Rules (assessment policy):
  - A 200 status alone is not trusted (SPA catch-alls / soft-404 pages can
    return 200 with the homepage instead of a real 404). The body must
    actually contain a "User-agent:" line — the one mandatory directive in
    any real robots.txt — before it's treated as a genuine hit.
  - "Disallow:" directives are NOT treated as a vulnerability, regardless of
    the paths they list → NOT VULNERABLE (info).
  - Any "Allow:" directive present → INFORMATIONAL. Allow lines explicitly
    disclose crawlable paths and are the only trigger for a finding here.
  - Requests follow redirects normally (e.g. a site-wide http -> https
    upgrade on the SAME path still counts as a genuine hit). But if a path
    redirects to a DIFFERENT path (e.g. a catch-all redirect to the
    homepage), it is treated as not present.
"""

import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding

ROBOTS_PATHS = ["/robots.txt", "/robot.txt"]


class RobotsModule(BaseModule):
    name = "robots"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for path in ROBOTS_PATHS:
            try:
                # Follow redirects normally — only skip if it lands on a
                # DIFFERENT path (e.g. a catch-all redirect to the homepage).
                response = await self.get(path)

                if self.redirected_elsewhere(response, path):
                    continue

                if response.status_code != 200:
                    continue

                body = response.text

                # Content verification — every real robots.txt has at least
                # one User-agent line (the one mandatory directive in the
                # spec). If it's missing, what we got back is the homepage/
                # login/error page in disguise — try the next path variant.
                if "user-agent:" not in body.lower():
                    continue

                url         = self.scope.build_url(path)
                allow_paths = self._extract_allow_paths(body)

                all_lines = "\n".join(
                    f"  {line}" for line in body.strip().splitlines()[:30]
                )
                req_line = (
                    f"GET {path} HTTP/1.1\n"
                    f"Host: {self.scope.target_host}\n"
                    f"Cookie: <session_cookie>"
                )

                if not allow_paths:
                    # Only Disallow directives (or none). Per assessment policy,
                    # Disallow entries are NOT treated as disclosure — not
                    # vulnerable, regardless of the paths they list.
                    findings.append(self.make_finding(
                        title="robots.txt Found — Not Vulnerable",
                        severity="info",
                        description=(
                            "The robots.txt file is publicly accessible but contains only "
                            "Disallow directives (or none). Disallow entries are not treated "
                            "as an information-disclosure issue, so there is nothing to flag."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"HTTP Status: {response.status_code}\n\n"
                            f"File contents (first 30 lines):\n{all_lines}\n\n"
                            f"No Allow directives found."
                        ),
                        affected_urls=[url],
                        request_data=req_line,
                        response_data=body[:800],
                        remediation="No action required.",
                    ))
                    continue

                # One or more Allow: directives present → informational.
                findings.append(self.make_finding(
                    title="robots.txt Discloses Allowed Paths (Informational)",
                    severity="info",
                    description=(
                        "The robots.txt file is publicly accessible and contains explicit "
                        "Allow: directives. These disclose specific paths the site marks as "
                        "crawlable. This is an informational finding — the paths are visible "
                        "to anyone who reads the file."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"HTTP Status: {response.status_code}\n\n"
                        f"File contents (first 30 lines):\n{all_lines}\n\n"
                        "Allow directives found:\n"
                        + "\n".join(f"  Allow: {p}" for p in allow_paths)
                    ),
                    affected_urls=[url],
                    request_data=req_line,
                    response_data=body[:800],
                    remediation=(
                        "Avoid listing internal or sensitive paths in robots.txt.\n"
                        "Enforce access control at the application level rather than relying "
                        "on robots.txt directives."
                    ),
                ))

            except httpx.RequestError:
                continue

        return findings

    @staticmethod
    def _extract_allow_paths(content: str) -> list[str]:
        """
        Extract paths from "Allow:" lines in robots.txt.

        Only "Allow:" directives are collected — their presence is what makes
        the file an (informational) disclosure under the assessment policy.
        "Disallow:" lines are deliberately ignored. A blank value is skipped.
        """
        paths = []
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("allow:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    path = parts[1].strip()
                    if path:
                        paths.append(path)
        return paths