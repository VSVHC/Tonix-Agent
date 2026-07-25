"""
modules/git_enum.py
────────────────────
Checks for an exposed Git repository.

Paths checked (narrowed to exactly these 4):
  /.git/HEAD
  /.git/config
  /.git/         (directory listing)
  /.gitignore

Verification approach — CONTENT-based, not status-code-based:
  A 200 status alone is not trusted. Many sites (SPA frameworks, custom
  error pages) return 200 for paths that don't really exist — serving the
  homepage, the login page, or a "soft 404" page instead of a real 404.

  For every path, three things must all be true before it's reported:
    1. No redirect to a DIFFERENT path (a same-path http -> https upgrade
       is fine and still checked normally).
    2. HTTP status is 200.
    3. The response BODY actually looks like the real file — not the
       homepage/login page in disguise.

Severity:
  Critical : /.git/config, /.git/ (directory listing)
  High     : /.git/HEAD, /.gitignore
"""

import re
import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding

# A real HEAD / config / .gitignore file is plain text — it is never an
# HTML page. If we see HTML markers, what we got back is almost certainly
# the homepage/login/error page, not the real file.
HTML_MARKERS = ("<!doctype html", "<html", "<head>", "<body")


class GitEnumModule(BaseModule):
    name = "git_enum"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for check in (
            self._check_head,
            self._check_config,
            self._check_directory_listing,
            self._check_gitignore,
        ):
            try:
                finding = await check()
                if finding:
                    findings.append(finding)
            except httpx.RequestError:
                continue

        return findings

    # ─────────────────────────────────────────────────────
    #  Individual path checks
    # ─────────────────────────────────────────────────────

    async def _check_head(self):
        path = "/.git/HEAD"
        response = await self.get(path)

        if self.redirected_elsewhere(response, path) or response.status_code != 200:
            return None

        body = response.text

        # Real HEAD file: "ref: refs/heads/<branch>" (normal) or a bare
        # 40-character commit SHA (detached HEAD state).
        looks_real = (
            "ref: refs/" in body
            or bool(re.match(r"^[0-9a-f]{40}\s*$", body.strip()))
        )
        if not looks_real or self._looks_like_html(body):
            return None

        return self.make_finding(
            title="Exposed Git File: /.git/HEAD",
            severity="high",
            description=(
                "The .git/HEAD file is publicly accessible, revealing the current "
                "branch name (or commit hash). This confirms a Git repository is "
                "exposed and is the first step toward reconstructing the full "
                "source code."
            ),
            evidence=(
                f"URL: {self.scope.build_url(path)}\n"
                f"HTTP Status: {response.status_code}\n\n"
                f"Response snippet:\n{body[:500]}"
            ),
            affected_urls=[self.scope.build_url(path)],
            request_data=self._req_line(path),
            response_data=body[:500],
            remediation=self._remediation(),
        )

    async def _check_config(self):
        path = "/.git/config"
        response = await self.get(path)

        if self.redirected_elsewhere(response, path) or response.status_code != 200:
            return None

        body = response.text

        # Every real git config file has a mandatory [core] section.
        looks_real = "[core]" in body.lower()
        if not looks_real or self._looks_like_html(body):
            return None

        return self.make_finding(
            title="Exposed Git File: /.git/config",
            severity="critical",
            description=(
                "The .git/config file is publicly accessible. It may contain remote "
                "repository URLs, author details, or even embedded credentials, and "
                "confirms a Git repository is exposed."
            ),
            evidence=(
                f"URL: {self.scope.build_url(path)}\n"
                f"HTTP Status: {response.status_code}\n\n"
                f"Response snippet:\n{body[:500]}"
            ),
            affected_urls=[self.scope.build_url(path)],
            request_data=self._req_line(path),
            response_data=body[:500],
            remediation=self._remediation(),
        )

    async def _check_directory_listing(self):
        path = "/.git/"
        response = await self.get(path)

        if self.redirected_elsewhere(response, path) or response.status_code != 200:
            return None

        body_lower = response.text.lower()

        # A real directory listing IS an HTML page — that's normal for an
        # autoindex, so we don't reject it for looking like HTML here.
        # Instead we require the literal "index of" phrase (how Apache/
        # nginx autoindex pages always announce themselves) PLUS at least
        # one git-internal filename actually being listed.
        has_index_phrase = "index of" in body_lower
        has_git_filename = any(
            name in body_lower for name in ("head", "config", "objects", "refs", "hooks")
        )
        if not (has_index_phrase and has_git_filename):
            return None

        return self.make_finding(
            title="Exposed Git Directory Listing: /.git/",
            severity="critical",
            description=(
                "Directory listing is enabled on /.git/, exposing the entire Git "
                "repository structure. An attacker can browse and download every "
                "file, fully reconstructing the source code and commit history."
            ),
            evidence=(
                f"URL: {self.scope.build_url(path)}\n"
                f"HTTP Status: {response.status_code}\n\n"
                f"Response snippet:\n{response.text[:500]}"
            ),
            affected_urls=[self.scope.build_url(path)],
            request_data=self._req_line(path),
            response_data=response.text[:500],
            remediation=self._remediation(),
        )

    async def _check_gitignore(self):
        path = "/.gitignore"
        response = await self.get(path)

        if self.redirected_elsewhere(response, path) or response.status_code != 200:
            return None

        body         = response.text
        content_type = response.headers.get("content-type", "").lower()

        # .gitignore has no fixed format, so we can't positively match its
        # content. Instead we rule out the common false positive: a server
        # quietly returning the homepage/login/error page with a 200.
        if not body.strip() or self._looks_like_html(body) or "html" in content_type:
            return None

        return self.make_finding(
            title="Exposed Git File: /.gitignore",
            severity="high",
            description=(
                ".gitignore is publicly accessible. While not sensitive on its own, "
                "it reveals internal directory and file naming conventions and "
                "confirms the presence of a Git repository worth probing further."
            ),
            evidence=(
                f"URL: {self.scope.build_url(path)}\n"
                f"HTTP Status: {response.status_code}\n"
                f"Content-Type: {content_type or 'N/A'}\n\n"
                f"Response snippet:\n{body[:500]}"
            ),
            affected_urls=[self.scope.build_url(path)],
            request_data=self._req_line(path),
            response_data=body[:500],
            remediation=self._remediation(),
        )

    # ─────────────────────────────────────────────────────
    #  Shared helpers
    # ─────────────────────────────────────────────────────

    @staticmethod
    def _looks_like_html(body: str) -> bool:
        lowered = body[:300].lower()
        return any(marker in lowered for marker in HTML_MARKERS)

    def _req_line(self, path: str) -> str:
        return (
            f"GET {path} HTTP/1.1\n"
            f"Host: {self.scope.target_host}\n"
            f"Cookie: <session_cookie>"
        )

    @staticmethod
    def _remediation() -> str:
        return (
            "Block public access to .git and related files at the web server level.\n"
            "Nginx:  location ~ /\\.git { deny all; return 404; }\n"
            "Apache: RedirectMatch 404 /\\.git\n"
            "Remove the .git directory from the web root entirely.\n"
            "Rotate any credentials or secrets found in the repository immediately."
        )
