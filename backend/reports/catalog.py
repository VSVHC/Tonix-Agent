"""
reports/catalog.py
──────────────────
Static test-case catalog for the security assessment report.

Every scan module maps to one catalogued test case. The report renders ALL
test cases — VULNERABLE, NOT VULNERABLE, and NOT APPLICABLE — using this
curated metadata:

    id                — TC-01 … TC-19 (ordered like the scan runs)
    name              — must equal the module's `name` attribute (finding key)
    title             — human test-case title
    module            — source module filename
    description       — what the test checks and why it matters
    cvss_score        — representative CVSS v3.1 base score for the vuln class
    cvss_vector       — the CVSS v3.1 base vector string
    severity          — default band (used when no live finding overrides it)
    parameters        — the request parameter(s)/surface the test touches
    references        — current, authoritative reference links (OWASP/CWE/MDN)
    reproduction      — numbered reproduction steps
    remediation       — how to fix
    sample_code       — always "N/A" for this automated assessment

CVSS scores are curated per vulnerability class, not computed live. When a
live finding exists its severity is shown alongside the catalogued score.
"""

# Order mirrors ALL_MODULES in orchestrator.py so TC numbering is stable.
TEST_CASES: list[dict] = [
    {
        "id": "TC-01", "name": "crossdomain", "module": "crossdomain.py",
        "title": "Cross-Domain Policy",
        "description": (
            "Checks for /crossdomain.xml (Adobe Flash) and /clientaccesspolicy.xml "
            "(Microsoft Silverlight) cross-domain policy files. A wildcard domain "
            "(*) lets any origin make cross-domain requests with the victim's "
            "credentials; permissive rules widen the trust boundary unnecessarily."
        ),
        "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "high",
        "parameters": "URL path (/crossdomain.xml, /clientaccesspolicy.xml)",
        "references": [
            "OWASP WSTG v4.2 — Testing for Cross Domain Policy: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/",
            "CWE-942: Permissive Cross-domain Policy with Untrusted Domains: https://cwe.mitre.org/data/definitions/942.html",
            "Adobe Cross-Domain Policy Specification: https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf",
        ],
        "reproduction": [
            "Request GET /crossdomain.xml on the target host.",
            "Request GET /clientaccesspolicy.xml on the target host.",
            "If either returns HTTP 200, inspect the body.",
            "Look for <allow-access-from domain=\"*\"/> or overly broad domains.",
        ],
        "remediation": (
            "Remove crossdomain.xml / clientaccesspolicy.xml if Flash/Silverlight is "
            "not used. If required, replace wildcards with an explicit allowlist of "
            "trusted domains. Prefer modern CORS headers over legacy policy files."
        ),
    },
    {
        "id": "TC-02", "name": "sitemap", "module": "sitemap.py",
        "title": "Sitemap Disclosure",
        "description": (
            "Checks for publicly accessible sitemap files (/sitemap.xml, "
            "/sitemap_index.xml, /sitemap1.xml, /wp-sitemap.xml). Sitemaps disclose "
            "the application's URL structure and can reveal endpoints not intended "
            "for discovery. Informational on its own."
        ),
        "cvss_score": 0.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "severity": "info",
        "parameters": "URL path (/sitemap.xml and variants)",
        "references": [
            "OWASP WSTG v4.2 — Review Webserver Metafiles for Information Leakage: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
            "sitemaps.org Protocol: https://www.sitemaps.org/protocol.html",
        ],
        "reproduction": [
            "Request GET /sitemap.xml (and /sitemap_index.xml, /sitemap1.xml, /wp-sitemap.xml).",
            "If any returns HTTP 200, enumerate the URLs disclosed.",
            "Review whether any disclosed path is sensitive or unlinked.",
        ],
        "remediation": (
            "Sitemaps are usually intentional for SEO. Ensure they do not list "
            "admin, staging, or internal-only endpoints. Restrict or remove sitemaps "
            "that leak non-public URL structure."
        ),
    },
    {
        "id": "TC-03", "name": "robots", "module": "robots.py",
        "title": "Robots.txt Disclosure",
        "description": (
            "Checks /robots.txt for Disallow entries. While robots.txt is a normal "
            "file, Disallow rules often point directly at sensitive or hidden paths "
            "(admin panels, backups, APIs) that an attacker can then target."
        ),
        "cvss_score": 0.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "severity": "info",
        "parameters": "URL path (/robots.txt)",
        "references": [
            "OWASP WSTG v4.2 — Review Webserver Metafiles for Information Leakage: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
            "Google — robots.txt Specifications: https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt",
        ],
        "reproduction": [
            "Request GET /robots.txt on the target host.",
            "If HTTP 200, read each Disallow / Allow directive.",
            "Manually browse the Disallow-ed paths to check for exposure.",
        ],
        "remediation": (
            "Do not rely on robots.txt for security — it is public and advisory only. "
            "Never list sensitive paths in it. Protect sensitive areas with "
            "authentication and authorization, not obscurity."
        ),
    },
    {
        "id": "TC-04", "name": "git_enum", "module": "git_enum.py",
        "title": "Git Repository Exposure",
        "description": (
            "Checks for an exposed .git directory (/.git/HEAD, /.git/config, /.git/, "
            "/.gitignore). An exposed repository lets an attacker reconstruct the "
            "full source code and commit history, and may leak credentials or "
            "internal remote URLs from the config."
        ),
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "parameters": "URL path (/.git/HEAD, /.git/config, /.git/, /.gitignore)",
        "references": [
            "OWASP WSTG v4.2 — Review Old Backup and Unreferenced Files for Sensitive Information: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
            "CWE-527: Exposure of Version-Control Repository to an Unauthorized Control Sphere: https://cwe.mitre.org/data/definitions/527.html",
        ],
        "reproduction": [
            "Request GET /.git/HEAD and confirm a 'ref: refs/heads/...' body.",
            "Request GET /.git/config and confirm a [core] section is returned.",
            "Request GET /.git/ to check for directory listing of git internals.",
            "If exposed, tools like git-dumper can reconstruct the source tree.",
        ],
        "remediation": (
            "Block public access to .git at the web server (e.g. nginx: "
            "location ~ /\\.git { deny all; return 404; }). Remove the .git directory "
            "from the web root. Rotate any credentials or secrets found in history."
        ),
    },
    {
        "id": "TC-05", "name": "headers", "module": "headers.py",
        "title": "Security Response Headers",
        "description": (
            "Audits for missing HTTP security headers: Strict-Transport-Security, "
            "X-Content-Type-Options, Content-Security-Policy, Referrer-Policy, and "
            "Permissions-Policy. Their absence weakens defense-in-depth against XSS, "
            "MIME sniffing, protocol downgrade, and data leakage."
        ),
        "cvss_score": 3.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
        "severity": "low",
        "parameters": "HTTP response headers",
        "references": [
            "OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/",
            "MDN — HTTP Security Headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
            "CWE-693: Protection Mechanism Failure: https://cwe.mitre.org/data/definitions/693.html",
        ],
        "reproduction": [
            "Send GET / and capture all response headers.",
            "Check for presence of each security header listed above.",
            "A header that is absent is reported as a finding.",
        ],
        "remediation": (
            "Add the missing headers at the web server or application layer, e.g. "
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload, "
            "X-Content-Type-Options: nosniff, and a restrictive Content-Security-Policy."
        ),
    },
    {
        "id": "TC-06", "name": "web_server", "module": "web_server.py",
        "title": "Web Server Fingerprinting",
        "description": (
            "Inspects Server and X-Powered-By response headers that disclose the web "
            "server product and version. Version disclosure helps an attacker match "
            "the target to known CVEs and craft targeted exploits."
        ),
        "cvss_score": 3.1, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "severity": "low",
        "parameters": "HTTP response headers (Server, X-Powered-By)",
        "references": [
            "OWASP WSTG v4.2 — Fingerprint Web Server: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
            "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor: https://cwe.mitre.org/data/definitions/200.html",
        ],
        "reproduction": [
            "Send GET / and read the Server and X-Powered-By headers.",
            "Note any product name and version string disclosed.",
            "Cross-reference the version against public CVE databases.",
        ],
        "remediation": (
            "Suppress or genericise version banners (e.g. nginx server_tokens off; "
            "Apache ServerTokens Prod). Remove X-Powered-By. Keep the server patched "
            "regardless, since obscurity is not a control."
        ),
    },
    {
        "id": "TC-07", "name": "clickjacking", "module": "clickjacking.py",
        "title": "Clickjacking Protection",
        "description": (
            "Checks whether the application prevents being framed via "
            "X-Frame-Options or a Content-Security-Policy frame-ancestors directive. "
            "Without framing protection, an attacker can overlay the site in a "
            "hidden iframe and trick users into clicking (UI redress / clickjacking)."
        ),
        "cvss_score": 3.7, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "severity": "low",
        "parameters": "HTTP response headers (X-Frame-Options, CSP frame-ancestors)",
        "references": [
            "OWASP — Clickjacking Defense Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            "CWE-1021: Improper Restriction of Rendered UI Layers or Frames: https://cwe.mitre.org/data/definitions/1021.html",
            "MDN — X-Frame-Options: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        ],
        "reproduction": [
            "Send GET / and inspect for X-Frame-Options or CSP frame-ancestors.",
            "If neither is present, the page can be framed by any origin.",
            "Confirm by loading the target inside an <iframe> on an attacker page.",
        ],
        "remediation": (
            "Set Content-Security-Policy: frame-ancestors 'self' (or a trusted list), "
            "and/or X-Frame-Options: DENY / SAMEORIGIN on all HTML responses."
        ),
    },
    {
        "id": "TC-08", "name": "error_exceptions", "module": "error_exceptions.py",
        "title": "Error & Exception Disclosure",
        "description": (
            "Sends malformed paths and query strings to trigger verbose errors, and "
            "actively confirms reflected XSS and boolean-based blind SQL injection. "
            "Verbose stack traces disclose internal structure; confirmed XSS/SQLi are "
            "directly exploitable."
        ),
        "cvss_score": 5.3, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "severity": "medium",
        "parameters": "Query string parameters (e.g. id, q) and URL path",
        "references": [
            "OWASP WSTG v4.2 — Testing for SQL Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
            "OWASP WSTG v4.2 — Testing for Reflected Cross Site Scripting: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
            "CWE-89: SQL Injection: https://cwe.mitre.org/data/definitions/89.html — CWE-79: Cross-site Scripting: https://cwe.mitre.org/data/definitions/79.html",
        ],
        "reproduction": [
            "Append error-triggering payloads to URLs (e.g. /%3c%3e, ?id=<script>).",
            "For XSS: inject a uniquely-marked <script> and confirm it reflects unescaped in HTML.",
            "For SQLi: compare a clean baseline vs an always-TRUE and always-FALSE condition on a parameter.",
            "A TRUE response matching baseline while FALSE diverges confirms blind SQLi.",
        ],
        "remediation": (
            "Return generic error pages; never expose stack traces in production. Use "
            "parameterized queries / prepared statements for all database access. "
            "HTML-encode all user-controlled output and add a Content-Security-Policy."
        ),
    },
    {
        "id": "TC-09", "name": "host_header", "module": "host_header.py",
        "title": "Host Header Injection",
        "description": (
            "Sends a spoofed Host header and checks whether the application reflects "
            "it into responses (links, redirects, absolute URLs). Host header "
            "injection enables web cache poisoning, password-reset poisoning, and "
            "routing-based attacks."
        ),
        "cvss_score": 2.2, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N",
        "severity": "low",
        "parameters": "HTTP Host header (and X-Forwarded-Host)",
        "references": [
            "OWASP WSTG v4.2 — Testing for Host Header Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection",
            "CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax: https://cwe.mitre.org/data/definitions/644.html",
            "PortSwigger — HTTP Host header attacks: https://portswigger.net/web-security/host-header",
        ],
        "reproduction": [
            "Send a request with Host: evil.example.com (or an injected value).",
            "Inspect the response for the spoofed host in links, redirects, or headers.",
            "If reflected, test password-reset and cache-poisoning impact.",
        ],
        "remediation": (
            "Validate the Host header against an allowlist of expected domains. Use "
            "absolute, hard-coded canonical URLs for security-sensitive links (e.g. "
            "password reset). Do not trust Host / X-Forwarded-Host for URL generation."
        ),
    },
    {
        "id": "TC-10", "name": "http_bypass", "module": "http_bypass.py",
        "title": "HTTP Access & Bypass",
        "description": (
            "Confirms the application is reachable in cleartext on port 80 while a "
            "secure HTTPS endpoint also exists, without enforcing a redirect. An "
            "attacker can force a protocol downgrade (SSL stripping) and intercept "
            "traffic even though HTTPS is available."
        ),
        "cvss_score": 7.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "severity": "high",
        "parameters": "URL scheme / port (http:// on port 80)",
        "references": [
            "OWASP WSTG v4.2 — Testing for Weak Transport Layer Security: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
            "CWE-319: Cleartext Transmission of Sensitive Information: https://cwe.mitre.org/data/definitions/319.html",
            "MDN — Strict-Transport-Security: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        ],
        "reproduction": [
            "Request http://target/ on port 80 without following redirects.",
            "Confirm content is served (2xx) rather than a 301/302 to https://.",
            "Confirm HTTPS is available on port 443.",
        ],
        "remediation": (
            "Redirect all HTTP (port 80) traffic to HTTPS with a 301. Enable HSTS "
            "with preload (Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload) to prevent SSL-stripping downgrades."
        ),
    },
    {
        "id": "TC-11", "name": "trace", "module": "trace.py",
        "title": "HTTP TRACE Method",
        "description": (
            "Checks whether the HTTP TRACE method is enabled. TRACE echoes the "
            "request back and, combined with other flaws, enables Cross-Site Tracing "
            "(XST) to read otherwise-protected headers such as cookies."
        ),
        "cvss_score": 2.7, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N",
        "severity": "low",
        "parameters": "HTTP request method (TRACE)",
        "references": [
            "OWASP WSTG v4.2 — Test HTTP Methods: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
            "CWE-16: Configuration: https://cwe.mitre.org/data/definitions/16.html",
        ],
        "reproduction": [
            "Send a TRACE / request to the target.",
            "If the response is 200 and echoes the request, TRACE is enabled.",
            "Assess XST impact where request headers can be reflected to script.",
        ],
        "remediation": (
            "Disable the TRACE method at the web server (e.g. Apache TraceEnable Off; "
            "nginx: reject via limit_except). Allow only the HTTP methods the "
            "application actually requires."
        ),
    },
    {
        "id": "TC-12", "name": "autocomplete", "module": "autocomplete.py",
        "title": "Password Autocomplete",
        "description": (
            "Checks whether password / sensitive input fields allow browser "
            "autocomplete. Cached credentials on shared or compromised devices can be "
            "recovered by a subsequent user or malware."
        ),
        "cvss_score": 0.0, "cvss_vector": "N/A",
        "severity": "info",
        "parameters": "HTML form input fields (autocomplete attribute)",
        "references": [
            "OWASP WSTG v4.2 — Testing for Vulnerable Remember Password: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password",
            "MDN — Turning off autocompletion: https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Turning_off_form_autocompletion",
        ],
        "reproduction": [
            "Load a page containing a password or sensitive field.",
            "Inspect the input's autocomplete attribute in the HTML.",
            "If autocomplete is not 'off'/'new-password', it is flagged.",
        ],
        "remediation": (
            "Set autocomplete=\"off\" (or \"new-password\" for password creation) on "
            "sensitive fields. Note that browser behaviour varies; treat this as "
            "defense-in-depth alongside device security guidance."
        ),
    },
    {
        "id": "TC-13", "name": "req_splitting", "module": "req_splitting.py",
        "title": "HTTP Request Splitting (CRLF)",
        "description": (
            "Injects CR/LF sequences into request components to test for CRLF "
            "injection / request splitting. Successful injection enables header "
            "injection, cache poisoning, and response manipulation."
        ),
        "cvss_score": 8.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
        "severity": "high",
        "parameters": "URL path / query parameters (CRLF payloads)",
        "references": [
            "OWASP WSTG v4.2 — Testing for HTTP Splitting Smuggling: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling",
            "CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers: https://cwe.mitre.org/data/definitions/113.html",
        ],
        "reproduction": [
            "Inject encoded CRLF (%0d%0a) payloads into parameters reflected into requests/headers.",
            "Observe whether the injected header or line break is honoured.",
            "Confirm the split alters the request/response structure.",
        ],
        "remediation": (
            "Strip or reject CR (%0d) and LF (%0a) characters from all user input "
            "used in headers, redirects, or upstream requests. Use framework APIs "
            "that encode header values safely."
        ),
    },
    {
        "id": "TC-14", "name": "res_splitting", "module": "res_splitting.py",
        "title": "HTTP Response Splitting (CRLF)",
        "description": (
            "Injects CR/LF sequences into parameters reflected into response headers "
            "(e.g. Location, Set-Cookie). Response splitting enables header injection, "
            "cache poisoning, and reflected XSS via crafted responses."
        ),
        "cvss_score": 8.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
        "severity": "high",
        "parameters": "Query parameters reflected into response headers",
        "references": [
            "OWASP WSTG v4.2 — Testing for HTTP Splitting Smuggling: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling",
            "CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers: https://cwe.mitre.org/data/definitions/113.html",
        ],
        "reproduction": [
            "Inject %0d%0a payloads into parameters that appear in response headers.",
            "Check whether an injected header (e.g. Set-Cookie) appears in the response.",
            "Confirm the response can be split into attacker-controlled content.",
        ],
        "remediation": (
            "Encode/strip CRLF from any user input placed in response headers. Prefer "
            "framework redirect/cookie APIs that neutralize control characters. "
            "Validate redirect targets against an allowlist."
        ),
    },
    {
        "id": "TC-15", "name": "directory_listing", "module": "directory_listing.py",
        "title": "Directory Listing",
        "description": (
            "Checks common directories for auto-index (directory listing) pages. An "
            "enabled listing exposes files not meant to be public — backups, configs, "
            "source, and other unreferenced content."
        ),
        "cvss_score": 3.7, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "severity": "low",
        "parameters": "URL path (common directories)",
        "references": [
            "OWASP WSTG v4.2 — Test Directory Traversal / File Inclusion & Enumerate Infrastructure: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
            "CWE-548: Exposure of Information Through Directory Listing: https://cwe.mitre.org/data/definitions/548.html",
        ],
        "reproduction": [
            "Request common directory paths (e.g. /uploads/, /backup/, /assets/).",
            "Look for an 'Index of /' auto-index page listing files.",
            "Download any exposed sensitive files to confirm impact.",
        ],
        "remediation": (
            "Disable auto-indexing (Apache: Options -Indexes; nginx: autoindex off). "
            "Place an index file in served directories and restrict access to "
            "non-public folders."
        ),
    },
    {
        "id": "TC-16", "name": "js_enum", "module": "js_enum.py",
        "title": "JavaScript Secret Enumeration",
        "description": (
            "Scans linked JavaScript for hard-coded secrets — API keys, tokens, cloud "
            "credentials, and internal endpoints. Secrets embedded in client-side JS "
            "are fully recoverable by any visitor."
        ),
        "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "high",
        "parameters": "JavaScript file contents (.js resources)",
        "references": [
            "OWASP WSTG v4.2 — Testing for Sensitive Information in JavaScript / Client-side: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/",
            "CWE-798: Use of Hard-coded Credentials: https://cwe.mitre.org/data/definitions/798.html",
        ],
        "reproduction": [
            "Collect all .js files referenced by the application.",
            "Search their contents for key/token/secret patterns.",
            "Validate any candidate secret is live and in scope before reporting.",
        ],
        "remediation": (
            "Never ship secrets in client-side code. Move secrets server-side, proxy "
            "third-party calls through the backend, and rotate any exposed key "
            "immediately. Add secret scanning to CI."
        ),
    },
    {
        "id": "TC-17", "name": "username_enum", "module": "username_enum.py",
        "title": "Username Enumeration",
        "description": (
            "Tests login, password-reset, and signup forms for behaviour that reveals "
            "whether an account exists (differential responses or distinct error "
            "messages). Account enumeration enables targeted credential stuffing and "
            "phishing."
        ),
        "cvss_score": 3.7, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "severity": "low",
        "parameters": "Auth form fields (username/email) on login, reset, signup",
        "references": [
            "OWASP WSTG v4.2 — Testing for Account Enumeration and Guessable User Account: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
            "CWE-204: Observable Response Discrepancy: https://cwe.mitre.org/data/definitions/204.html",
        ],
        "reproduction": [
            "Submit a known-good and a random account to the target form.",
            "Compare status code, response length, and message across submissions.",
            "A consistent, distinguishable difference confirms enumeration.",
        ],
        "remediation": (
            "Return an identical generic message, status code, and response size for "
            "every failed attempt. Use neutral wording for reset/signup ('If this "
            "email is registered, you will receive a link.') and add consistent timing."
        ),
    },
    {
        "id": "TC-18", "name": "captcha", "module": "captcha.py",
        "title": "CAPTCHA Not Enabled",
        "description": (
            "Checks authentication-related pages (login, reset, signup) for a CAPTCHA "
            "or equivalent bot-protection widget. Without one, forms are exposed to "
            "automated brute-force, credential stuffing, and mass registration/spam."
        ),
        "cvss_score": 0.0, "cvss_vector": "N/A",
        "severity": "info",
        "parameters": "Auth pages (login/reset/signup) — presence of CAPTCHA widget",
        "references": [
            "OWASP — Credential Stuffing Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html",
            "OWASP — Blocking Brute Force Attacks: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
            "CWE-307: Improper Restriction of Excessive Authentication Attempts: https://cwe.mitre.org/data/definitions/307.html",
        ],
        "reproduction": [
            "Load each authentication page (login, reset, signup).",
            "Inspect the HTML for a reCAPTCHA/hCaptcha/Turnstile or equivalent widget.",
            "If no CAPTCHA is present, the page is flagged as vulnerable.",
        ],
        "remediation": (
            "Add a CAPTCHA (reCAPTCHA v3, hCaptcha, or Cloudflare Turnstile) to "
            "authentication forms, complemented by rate limiting and account lockout "
            "to blunt automated attacks."
        ),
    },
    {
        "id": "TC-19", "name": "unencrypted_communication", "module": "unencrypted_communication.py",
        "title": "Unencrypted Communication",
        "description": (
            "Confirms the application is served over plain HTTP with no working HTTPS "
            "service. All traffic — including credentials and session tokens — is "
            "transmitted in cleartext and can be read or modified by any attacker on "
            "the network path (MITM)."
        ),
        "cvss_score": 7.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "severity": "high",
        "parameters": "URL scheme / port (http:// with no HTTPS on 443)",
        "references": [
            "OWASP WSTG v4.2 — Testing for Weak Transport Layer Security: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
            "CWE-319: Cleartext Transmission of Sensitive Information: https://cwe.mitre.org/data/definitions/319.html",
        ],
        "reproduction": [
            "Request http://target/ and confirm content is served in cleartext.",
            "Confirm https://target/ (port 443) does not respond / has no valid service.",
            "Capture traffic to demonstrate cleartext credential/session exposure.",
        ],
        "remediation": (
            "Deploy a valid TLS certificate and serve the application over HTTPS. "
            "Redirect all HTTP to HTTPS with a 301 and enable HSTS "
            "(Strict-Transport-Security: max-age=31536000; includeSubDomains)."
        ),
    },
    {
        "id": "TC-20", "name": "cors", "module": "cors.py",
        "title": "Insecure CORS Configuration",
        "description": (
            "Tests every discovered URL for a permissive or broken Cross-Origin "
            "Resource Sharing policy. When the server reflects an attacker-controlled "
            "Origin into Access-Control-Allow-Origin and also sets "
            "Access-Control-Allow-Credentials: true, any website can make authenticated "
            "cross-origin requests as the victim and read the responses — a cross-site "
            "data-theft vulnerability. Trusting the 'null' origin or matching origins by "
            "prefix/suffix are related bypasses."
        ),
        "cvss_score": 2.6, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N",
        "severity": "low",
        "parameters": "HTTP Origin request header",
        "references": [
            "OWASP WSTG v4.2 — Testing Cross Origin Resource Sharing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
            "PortSwigger — CORS misconfiguration: https://portswigger.net/web-security/cors",
            "MDN — Cross-Origin Resource Sharing (CORS): https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            "CWE-942: Permissive Cross-domain Policy with Untrusted Domains: https://cwe.mitre.org/data/definitions/942.html",
        ],
        "reproduction": [
            "Send a request to the endpoint with an attacker-controlled Origin header (e.g. Origin: https://evil.attacker.com).",
            "Inspect the response's Access-Control-Allow-Origin (ACAO) and Access-Control-Allow-Credentials (ACAC) headers.",
            "If ACAO reflects the attacker origin exactly and ACAC is true, authenticated cross-origin reads are possible.",
            "Also test Origin: null and Origin: https://<target-host>.attacker.com to detect null-origin trust and broken suffix validation.",
        ],
        "remediation": (
            "Do not reflect the Origin header into Access-Control-Allow-Origin. Validate "
            "Origin against a strict allowlist of exact trusted origins, never trust 'null', "
            "and only send Access-Control-Allow-Credentials: true for allowlisted origins "
            "(never with a wildcard). Omit CORS headers entirely where cross-origin access "
            "is not required."
        ),
    },
]

# ─────────────────────────────────────────────────────────
#  Manual test cases (Security Tools) — JWT.
#  These are NOT run during an automated scan. They appear in a report ONLY
#  when the user explicitly attaches a result (see _build_results), so they
#  are kept out of TEST_CASES to avoid polluting every scan report.
# ─────────────────────────────────────────────────────────
MANUAL_TEST_CASES: list[dict] = [
    # ── JWT: one test case per forged-token / lifetime check ──────────────
    {
        "id": "TC-21", "name": "jwt_none", "module": "analysis/jwt_tool.py",
        "title": "JWT — None Algorithm",
        "description": (
            "Replays a token whose header algorithm is set to 'none' (unsigned) against "
            "your endpoint. If the server accepts it, it performs no signature check at "
            "all — an attacker can forge a token for any user."
        ),
        "cvss_score": 9.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
        "severity": "critical",
        "parameters": "Authorization: Bearer <JWT> (header alg=none)",
        "references": [
            "OWASP WSTG v4.2 — Testing JSON Web Tokens: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
            "CWE-347: Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html",
            "PortSwigger — JWT attacks: https://portswigger.net/web-security/jwt",
        ],
        "reproduction": [
            "Capture a valid JWT and the endpoint that consumes it.",
            "Set the header 'alg' to 'none' and remove the signature.",
            "Send the forged token as the Bearer credential.",
            "HTTP 200 with a normal body means the 'none' algorithm is accepted.",
        ],
        "remediation": (
            "Reject the 'none' algorithm outright and pin the expected algorithm "
            "server-side. Never let the attacker-controlled header 'alg' pick the "
            "verification path."
        ),
    },
    {
        "id": "TC-22", "name": "jwt_alg_swap", "module": "analysis/jwt_tool.py",
        "title": "JWT — Algorithm Swap (HS256↔RS256)",
        "description": (
            "Replays the token with HS256↔RS256 swapped to exploit algorithm confusion, "
            "where the RSA public key is misused as an HMAC secret. Acceptance means the "
            "server lets the token's header choose how it is verified."
        ),
        "cvss_score": 8.2, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "high",
        "parameters": "Authorization: Bearer <JWT> (header alg swapped)",
        "references": [
            "CWE-347: Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html",
            "PortSwigger — JWT algorithm confusion: https://portswigger.net/web-security/jwt/algorithm-confusion",
        ],
        "reproduction": [
            "Capture a valid JWT and the endpoint that consumes it.",
            "Swap the header algorithm (HS256↔RS256) and re-sign accordingly.",
            "Send the forged token as the Bearer credential.",
            "HTTP 200 with a normal body means algorithm confusion is exploitable.",
        ],
        "remediation": (
            "Pin the expected algorithm server-side and verify with the correct key type. "
            "Do not select the verification algorithm from the token header."
        ),
    },
    {
        "id": "TC-23", "name": "jwt_empty_sig", "module": "analysis/jwt_tool.py",
        "title": "JWT — Empty Signature",
        "description": (
            "Replays the token with its signature stripped off. Acceptance means the "
            "server does not require or verify a signature at all."
        ),
        "cvss_score": 8.2, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "high",
        "parameters": "Authorization: Bearer <JWT> (signature removed)",
        "references": [
            "CWE-347: Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html",
            "PortSwigger — JWT attacks: https://portswigger.net/web-security/jwt",
        ],
        "reproduction": [
            "Capture a valid JWT and the endpoint that consumes it.",
            "Remove the signature segment, keeping the trailing dot.",
            "Send the forged token as the Bearer credential.",
            "HTTP 200 with a normal body means the signature is not verified.",
        ],
        "remediation": (
            "Require and verify a valid signature on every request; reject tokens with an "
            "empty or missing signature."
        ),
    },
    {
        "id": "TC-24", "name": "jwt_altered_sig", "module": "analysis/jwt_tool.py",
        "title": "JWT — Altered Signature",
        "description": (
            "Replays the token with its signature bytes altered. Acceptance means the "
            "server does not actually validate the signature against the payload."
        ),
        "cvss_score": 8.2, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "high",
        "parameters": "Authorization: Bearer <JWT> (signature tampered)",
        "references": [
            "CWE-347: Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html",
            "PortSwigger — JWT attacks: https://portswigger.net/web-security/jwt",
        ],
        "reproduction": [
            "Capture a valid JWT and the endpoint that consumes it.",
            "Alter the last bytes of the signature segment.",
            "Send the forged token as the Bearer credential.",
            "HTTP 200 with a normal body means the signature is not validated.",
        ],
        "remediation": (
            "Verify the signature cryptographically against the header and payload on every "
            "request; reject any token whose signature does not match."
        ),
    },
    {
        "id": "TC-25", "name": "jwt_expiry", "module": "analysis/jwt_tool.py",
        "title": "JWT — Token Expiration",
        "description": (
            "Checks the token lifetime (exp − iat). A window longer than 2 days, or a "
            "token with no expiry at all, is flagged as an excessive-lifetime weakness."
        ),
        "cvss_score": 0.0, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "severity": "info",
        "parameters": "JWT exp / iat claims",
        "references": [
            "OWASP WSTG v4.2 — Testing JSON Web Tokens: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
            "CWE-613: Insufficient Session Expiration: https://cwe.mitre.org/data/definitions/613.html",
        ],
        "reproduction": [
            "Decode the token and read the exp and iat claims.",
            "Compute the lifetime (exp − iat).",
            "A lifetime over 2 days, or no exp claim, is an excessive-lifetime weakness.",
        ],
        "remediation": (
            "Enforce short token lifetimes (well under 2 days) with refresh tokens, and "
            "validate exp on every request."
        ),
    },
]

# Fast lookup by module name — includes manual cases so the orchestrator's benign
# marker builder and the attach flow can resolve their catalog metadata.
BY_NAME: dict[str, dict] = {tc["name"]: tc for tc in (TEST_CASES + MANUAL_TEST_CASES)}


def cvss_band(score: float) -> str:
    """Map a CVSS v3.1 base score to its qualitative severity band."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"
