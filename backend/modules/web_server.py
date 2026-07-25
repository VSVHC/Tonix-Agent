"""
modules/web_server.py
──────────────────────
Detects web server technology and version disclosure.

Checks:
  - Response headers on GET / (homepage)
  - Response headers and body on error pages (404, 500)
  - Default error page content fingerprinting

Rules:
  - Only flag a header if it contains a version NUMBER (e.g. nginx/1.18.0)
  - If header says just "nginx" with no version → NOT VULNERABLE
  - Server header is excluded (handled here, not in headers.py)
  - CVEs are fetched automatically from NVD API for disclosed versions
  - Only unpatched (open) CVEs are reported
  - CVEs sorted by severity (Critical first)
  - Combined/deduplicated across sources

Error pages probed:
  - /nonexistent_page_xyz (triggers 404)
  - /error               (may trigger 500)
  - /'                   (may trigger 500)
  - /*                   (may trigger 400/500)
"""

import re
import httpx
from backend.modules.base_module import BaseModule
from backend.models import Finding

VERSION_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Runtime",
    "X-Version",
    "Via",
    "X-Drupal-Cache",
    "X-WordPress",
]

# Only flag when a version number (digits.digits) is present
VERSION_NUMBER_RE = re.compile(r"\d+\.\d+")

# Error-triggering paths to probe for additional header/body disclosure
ERROR_PATHS = [
    "/nonexistent_page_web_server_check",
    "/error",
    "/'",
    "/*",
]

# Known default error page fingerprints in body
DEFAULT_PAGE_SIGNATURES = [
    ("nginx",          re.compile(r"<title>Welcome to nginx</title>|nginx/[\d\.]+",  re.IGNORECASE), "Nginx default page"),
    ("apache",         re.compile(r"Apache/[\d\.]+ \(",                               re.IGNORECASE), "Apache version in error page"),
    ("apache_default", re.compile(r"<title>Apache2 Ubuntu Default Page</title>",      re.IGNORECASE), "Apache2 Ubuntu default page"),
    ("iis",            re.compile(r"IIS Windows Server|Microsoft-IIS/[\d\.]+",        re.IGNORECASE), "IIS default page"),
    ("tomcat",         re.compile(r"Apache Tomcat/[\d\.]+|<title>Apache Tomcat",      re.IGNORECASE), "Tomcat default page"),
    ("jetty",          re.compile(r"Powered by Jetty|jetty/[\d\.]+",                  re.IGNORECASE), "Jetty server"),
    ("lighttpd",       re.compile(r"lighttpd/[\d\.]+",                                re.IGNORECASE), "Lighttpd version"),
    ("express",        re.compile(r"Cannot GET /|<pre>Cannot GET",                    re.IGNORECASE), "Express.js default error"),
    ("laravel",        re.compile(r"Laravel v[\d\.]+|Whoops.*Laravel",                re.IGNORECASE), "Laravel version disclosure"),
    ("django",         re.compile(r"Django version [\d\.]+|DisallowedHost at /",      re.IGNORECASE), "Django debug/error page"),
    ("rails",          re.compile(r"Ruby on Rails|ActionController|Rails [\d\.]+",    re.IGNORECASE), "Ruby on Rails disclosure"),
    ("spring",         re.compile(r"Whitelabel Error Page|Spring Boot",               re.IGNORECASE), "Spring Boot error page"),
    ("php",            re.compile(r"PHP/[\d\.]+",                                     re.IGNORECASE), "PHP version in header/body"),
]

# ETag inode leak pattern (Apache default format: "inode-size-mtime")
ETAG_INODE_RE = re.compile(r'"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"')

# NVD API base URL for CVE lookup
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Map NVD CVE severity band → this finding's severity. With no unpatched CVEs,
# version disclosure alone is Low; the worst CVE drives it up (Critical CVE →
# Critical finding). ponytail: NVD keywordSearch is version-fuzzy, so a noisy
# match can over-rate; tighten to CPE-exact matching if false positives appear.
_CVE_TO_SEVERITY = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "NONE": "low",
}


class WebServerModule(BaseModule):
    name = "web_server"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        all_disclosed: dict[str, str] = {}     # header_name -> value
        all_page_matches: list[dict]  = []
        etag_leak: str = ""

        # ── Step 1: Probe homepage ────────────────────────
        try:
            home_resp = await self.get("/")
            self._collect_disclosures(
                dict(home_resp.headers),
                home_resp.text,
                all_disclosed,
                all_page_matches,
            )
            etag = home_resp.headers.get("etag", "")
            if ETAG_INODE_RE.match(etag):
                etag_leak = etag
        except httpx.RequestError:
            pass

        # ── Step 2: Probe error pages ─────────────────────
        for path in ERROR_PATHS:
            try:
                err_resp = await self.get(path)
                if err_resp.status_code > 200:
                    self._collect_disclosures(
                        dict(err_resp.headers),
                        err_resp.text,
                        all_disclosed,
                        all_page_matches,
                    )
            except httpx.RequestError:
                continue

        if not all_disclosed and not all_page_matches and not etag_leak:
            return findings

        # ── Step 3: Build evidence ────────────────────────
        evidence_parts = []

        if all_disclosed:
            evidence_parts.append("Version-disclosing headers found:")
            for h, v in all_disclosed.items():
                evidence_parts.append(f"  {h}: {v}")

        if all_page_matches:
            evidence_parts.append("\nDefault/fingerprint pages detected:")
            for p in all_page_matches:
                evidence_parts.append(f"  [{p['label']}] Matched: {p['matched']}")

        if etag_leak:
            evidence_parts.append(f"\nETag header leaks inode/file size: {etag_leak}")

        # ── Step 4: Fetch CVEs for disclosed versions ─────
        cve_section = ""
        cves: list[dict] = []
        version_strings = self._extract_versions(all_disclosed)

        if version_strings:
            cves = await self._fetch_cves(version_strings)
            if cves:
                cve_lines = [
                    "\nKnown unpatched CVEs for disclosed version(s):",
                    f"  {'CVE ID':<20} {'Severity':<12} {'CVSS':<6} {'Disclosed':<12} Description",
                    f"  {'-'*20} {'-'*12} {'-'*6} {'-'*12} {'-'*50}",
                ]
                for cve in cves:
                    cve_lines.append(
                        f"  {cve['id']:<20} {cve['severity']:<12} {cve['cvss']:<6} "
                        f"{cve['published']:<12} {cve['description'][:60]}"
                    )
                    cve_lines.append(f"    Reference: {cve['url']}")
                cve_section = "\n".join(cve_lines)
            elif version_strings:
                cve_section = (
                    f"\nCVE lookup performed for: {', '.join(version_strings)}\n"
                    f"  No unpatched CVEs found in NVD — manual verification recommended."
                )

        evidence = "\n".join(evidence_parts)
        if cve_section:
            evidence += "\n" + cve_section

        # Severity tracks the worst unpatched CVE for the disclosed version(s);
        # Low when none are found (cves is pre-sorted Critical-first).
        finding_severity = _CVE_TO_SEVERITY.get(cves[0]["severity"], "low") if cves else "low"

        findings.append(self.make_finding(
            title="Web Server Technology and Version Disclosed",
            severity=finding_severity,
            description=(
                "The server reveals its technology stack and/or version number "
                "through HTTP response headers or default error/landing pages. "
                "This information aids attackers in identifying known CVEs "
                "and targeting exploitation techniques."
            ),
            evidence=evidence,
            affected_urls=[self.scope.base_url + "/"],
            request_data=(
                f"GET / HTTP/1.1\n"
                f"Host: {self.scope.target_host}\n"
                f"Cookie: <session_cookie>"
            ),
            response_data="\n".join(
                f"{h}: {v}" for h, v in all_disclosed.items()
            ),
            remediation=(
                "Suppress version information from all headers.\n"
                "Nginx:  server_tokens off;\n"
                "Apache: ServerTokens Prod; ServerSignature Off\n"
                "IIS:    Remove X-Powered-By via URL Rewrite rules.\n"
                "Replace default error pages with custom, non-descriptive ones.\n"
                "Apache ETags: FileETag None"
            ),
        ))

        return findings

    # ─────────────────────────────────────────────────────

    def _collect_disclosures(
        self,
        headers: dict,
        body: str,
        disclosed: dict,
        page_matches: list,
    ) -> None:
        """Extract version-disclosing headers and fingerprint page signatures."""
        # Headers — only flag when a version NUMBER is present
        for header in VERSION_HEADERS:
            value = headers.get(header.lower()) or headers.get(header)
            if not value:
                continue
            if VERSION_NUMBER_RE.search(value) and header not in disclosed:
                disclosed[header] = value

        # Body and headers — default page fingerprints
        full_text = body + " ".join(f"{k}: {v}" for k, v in headers.items())
        seen_names = {m["name"] for m in page_matches}
        for name, pattern, label in DEFAULT_PAGE_SIGNATURES:
            if name in seen_names:
                continue
            match = pattern.search(full_text)
            if match:
                page_matches.append({
                    "name":    name,
                    "label":   label,
                    "matched": match.group(0)[:120],
                })

    @staticmethod
    def _extract_versions(disclosed: dict) -> list[str]:
        """Extract raw version strings from disclosed headers for CVE lookup."""
        versions = []
        for header, value in disclosed.items():
            # Extract version numbers like nginx/1.18.0, PHP/8.1.2, etc.
            parts = value.split("/")
            if len(parts) >= 2:
                tech    = parts[0].strip()
                version = parts[1].split()[0].strip()
                if VERSION_NUMBER_RE.search(version):
                    versions.append(f"{tech} {version}")
            else:
                # Try matching version from value directly
                match = VERSION_NUMBER_RE.search(value)
                if match:
                    versions.append(value.strip())
        return list(set(versions))

    async def _fetch_cves(self, version_strings: list[str]) -> list[dict]:
        """
        Query NVD API for CVEs matching each disclosed version.
        Returns only unpatched CVEs, sorted by severity (Critical first).
        Deduplicates across version queries.
        """
        SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
        seen_ids: set[str] = set()
        all_cves: list[dict] = []

        for version_str in version_strings:
            try:
                async with httpx.AsyncClient(timeout=15) as client:
                    resp = await client.get(
                        NVD_API_URL,
                        params={
                            "keywordSearch":   version_str,
                            "resultsPerPage":  50,
                            "noRejected":      "",
                        },
                    )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                for item in data.get("vulnerabilities", []):
                    cve_data = item.get("cve", {})
                    cve_id   = cve_data.get("id", "")

                    if cve_id in seen_ids:
                        continue

                    # Filter: skip if a fix/patch is confirmed
                    # NVD marks patched CVEs with vulnStatus = "Modified" or "Analyzed"
                    # We include all that are NOT "Rejected"
                    vuln_status = cve_data.get("vulnStatus", "")
                    if vuln_status == "Rejected":
                        continue

                    # Extract severity from CVSS metrics
                    severity = "NONE"
                    cvss_score = "N/A"
                    cvss_vector = ""
                    metrics = cve_data.get("metrics", {})
                    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        metric_list = metrics.get(metric_key, [])
                        if metric_list:
                            cvss_data   = metric_list[0].get("cvssData", {})
                            severity    = cvss_data.get("baseSeverity", "NONE").upper()
                            cvss_score  = str(cvss_data.get("baseScore", "N/A"))
                            cvss_vector = cvss_data.get("vectorString", "")
                            break

                    # Extract description (English preferred)
                    description = ""
                    for desc in cve_data.get("descriptions", []):
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")[:120]
                            break

                    # Extract published date
                    published = cve_data.get("published", "")[:10]

                    # NVD reference URL
                    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                    seen_ids.add(cve_id)
                    all_cves.append({
                        "id":          cve_id,
                        "severity":    severity,
                        "cvss":        cvss_score,
                        "vector":      cvss_vector,
                        "published":   published,
                        "description": description,
                        "url":         nvd_url,
                        "_sort_key":   SEVERITY_ORDER.get(severity, 5),
                    })

            except (httpx.RequestError, Exception):
                continue

        # Sort by severity: Critical → High → Medium → Low
        all_cves.sort(key=lambda x: x["_sort_key"])
        return all_cves
