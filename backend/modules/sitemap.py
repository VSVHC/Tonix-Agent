"""
modules/sitemap.py
───────────────────
Checks for publicly accessible sitemap files.

Paths checked:
  /sitemap.xml
  /sitemap_index.xml
  /sitemap1.xml
  /wp-sitemap.xml

Verification approach — CONTENT-based, not status-code-based:
  A 200 status alone is not trusted (SPA catch-alls / soft-404 pages can
  return 200 with the homepage instead of a real 404). The response body
  must actually contain <urlset> or <sitemapindex> — the only two valid
  root tags for a real XML sitemap — before it's treated as a genuine hit.

Reports existence as informational with a count of disclosed URLs.

Redirect handling:
  Requests follow redirects normally (e.g. a site-wide http -> https
  upgrade on the SAME path still counts as a genuine hit). But if a path
  redirects to a DIFFERENT path (e.g. a catch-all redirect to the
  homepage), it is treated as not present.
"""

import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding

SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap1.xml",
    "/wp-sitemap.xml",
]


class SitemapModule(BaseModule):
    name = "sitemap"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for path in SITEMAP_PATHS:
            try:
                # Follow redirects normally — only skip if it lands on a
                # DIFFERENT path (e.g. a catch-all redirect to the homepage).
                response = await self.get(path)

                if self.redirected_elsewhere(response, path):
                    continue

                if response.status_code != 200:
                    continue

                body = response.text

                # Content verification — a real XML sitemap always has one
                # of these two root tags. If neither is present, what we got
                # back is the homepage/login/error page, not a real sitemap —
                # try the next path instead of trusting this one.
                if "<urlset" not in body.lower() and "<sitemapindex" not in body.lower():
                    continue

                url       = self.scope.build_url(path)
                url_count = body.lower().count("<url>") or body.lower().count("<loc>")

                findings.append(self.make_finding(
                    title="sitemap.xml Publicly Accessible (Information Disclosure)",
                    severity="info",
                    description=(
                        "The sitemap.xml file is publicly accessible and enumerates "
                        "application URL paths. While intended for search engine indexing, "
                        "it provides attackers with a complete map of accessible endpoints "
                        "for further targeted testing."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"HTTP Status: {response.status_code}\n"
                        f"Approximate URLs disclosed: {url_count}\n\n"
                        f"File snippet:\n{body[:600]}"
                    ),
                    affected_urls=[url],
                    request_data=(
                        f"GET {path} HTTP/1.1\n"
                        f"Host: {self.scope.target_host}\n"
                        f"Cookie: <session_cookie>"
                    ),
                    response_data=body[:600],
                    remediation=(
                        "Review sitemap.xml to ensure no sensitive or unintended paths are listed.\n"
                        "Consider restricting access to authenticated users or removing the sitemap "
                        "if not required for SEO purposes."
                    ),
                ))
                break   # One sitemap finding is sufficient

            except httpx.RequestError:
                continue

        return findings
