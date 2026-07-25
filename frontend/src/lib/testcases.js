// Per-test-case metadata — mirrors backend/reports/catalog.py.
// Used by the Live Scan "Verification" section so non-vulnerable test cases can
// show the same Overview / Evidence / Request / Remediation fields as
// vulnerabilities, even when a module produced no finding.
export const TESTCASE_INFO = {
  crossdomain: {
    title: 'Cross-Domain Policy',
    description: 'Checks for /crossdomain.xml (Adobe Flash) and /clientaccesspolicy.xml (Microsoft Silverlight) cross-domain policy files. A wildcard domain (*) lets any origin make cross-domain requests with the victim\'s credentials.',
    remediation: 'Remove crossdomain.xml / clientaccesspolicy.xml if Flash/Silverlight is not used. If required, replace wildcards with an explicit allowlist of trusted domains. Prefer modern CORS headers over legacy policy files.',
  },
  sitemap: {
    title: 'Sitemap Disclosure',
    description: 'Checks for publicly accessible sitemap files (/sitemap.xml, /sitemap_index.xml, /sitemap1.xml, /wp-sitemap.xml). Sitemaps disclose the application\'s URL structure and can reveal endpoints not intended for discovery.',
    remediation: 'Sitemaps are usually intentional for SEO. Ensure they do not list admin, staging, or internal-only endpoints. Restrict or remove sitemaps that leak non-public URL structure.',
  },
  robots: {
    title: 'Robots.txt Disclosure',
    description: 'Checks /robots.txt for Disallow entries. Disallow rules often point directly at sensitive or hidden paths (admin panels, backups, APIs) that an attacker can then target.',
    remediation: 'Do not rely on robots.txt for security — it is public and advisory only. Never list sensitive paths in it. Protect sensitive areas with authentication and authorization, not obscurity.',
  },
  git_enum: {
    title: 'Git Repository Exposure',
    description: 'Checks for an exposed .git directory (/.git/HEAD, /.git/config, /.git/, /.gitignore). An exposed repository lets an attacker reconstruct the full source code and commit history, and may leak credentials.',
    remediation: 'Block public access to .git at the web server (e.g. nginx: location ~ /\\.git { deny all; return 404; }). Remove the .git directory from the web root. Rotate any credentials or secrets found in history.',
  },
  headers: {
    title: 'Security Response Headers',
    description: 'Audits for missing HTTP security headers: Strict-Transport-Security, X-Content-Type-Options, Content-Security-Policy, Referrer-Policy, and Permissions-Policy. Their absence weakens defense-in-depth against XSS, MIME sniffing, and downgrade attacks.',
    remediation: 'Add the missing headers at the web server or application layer, e.g. Strict-Transport-Security: max-age=31536000; includeSubDomains; preload, X-Content-Type-Options: nosniff, and a restrictive Content-Security-Policy.',
  },
  web_server: {
    title: 'Web Server Fingerprinting',
    description: 'Inspects Server and X-Powered-By response headers that disclose the web server product and version. Version disclosure helps an attacker match the target to known CVEs.',
    remediation: 'Suppress or genericise version banners (e.g. nginx server_tokens off; Apache ServerTokens Prod). Remove X-Powered-By. Keep the server patched regardless, since obscurity is not a control.',
  },
  clickjacking: {
    title: 'Clickjacking Protection',
    description: 'Checks whether the application prevents being framed via X-Frame-Options or a CSP frame-ancestors directive. Without framing protection, an attacker can overlay the site in a hidden iframe and trick users into clicking.',
    remediation: 'Set Content-Security-Policy: frame-ancestors \'self\' (or a trusted list), and/or X-Frame-Options: DENY / SAMEORIGIN on all HTML responses.',
  },
  error_exceptions: {
    title: 'Error & Exception Disclosure',
    description: 'Sends malformed paths and query strings to trigger verbose errors, and actively confirms reflected XSS and boolean-based blind SQL injection. Verbose stack traces disclose internal structure; confirmed XSS/SQLi are directly exploitable.',
    remediation: 'Return generic error pages; never expose stack traces in production. Use parameterized queries for all database access. HTML-encode all user-controlled output and add a Content-Security-Policy.',
  },
  host_header: {
    title: 'Host Header Injection',
    description: 'Sends a spoofed Host header and checks whether the application reflects it into responses (links, redirects, absolute URLs). Host header injection enables cache poisoning and password-reset poisoning.',
    remediation: 'Validate the Host header against an allowlist of expected domains. Use absolute, hard-coded canonical URLs for security-sensitive links. Do not trust Host / X-Forwarded-Host for URL generation.',
  },
  http_bypass: {
    title: 'HTTP Access & Bypass',
    description: 'Confirms the application is reachable in cleartext on port 80 while a secure HTTPS endpoint also exists, without enforcing a redirect. An attacker can force a protocol downgrade (SSL stripping) and intercept traffic.',
    remediation: 'Redirect all HTTP (port 80) traffic to HTTPS with a 301. Enable HSTS with preload (Strict-Transport-Security: max-age=31536000; includeSubDomains; preload) to prevent SSL-stripping downgrades.',
  },
  trace: {
    title: 'HTTP TRACE Method',
    description: 'Checks whether the HTTP TRACE method is enabled. TRACE echoes the request back and, combined with other flaws, enables Cross-Site Tracing (XST) to read otherwise-protected headers such as cookies.',
    remediation: 'Disable the TRACE method at the web server (e.g. Apache TraceEnable Off; nginx: reject via limit_except). Allow only the HTTP methods the application actually requires.',
  },
  autocomplete: {
    title: 'Password Autocomplete',
    description: 'Checks whether password / sensitive input fields allow browser autocomplete. Cached credentials on shared or compromised devices can be recovered by a subsequent user or malware.',
    remediation: 'Set autocomplete="off" (or "new-password" for password creation) on sensitive fields. Treat this as defense-in-depth alongside device security guidance.',
  },
  req_splitting: {
    title: 'HTTP Request Splitting (CRLF)',
    description: 'Injects CR/LF sequences into request components to test for CRLF injection / request splitting. Successful injection enables header injection, cache poisoning, and response manipulation.',
    remediation: 'Strip or reject CR (%0d) and LF (%0a) characters from all user input used in headers, redirects, or upstream requests. Use framework APIs that encode header values safely.',
  },
  res_splitting: {
    title: 'HTTP Response Splitting (CRLF)',
    description: 'Injects CR/LF sequences into parameters reflected into response headers (e.g. Location, Set-Cookie). Response splitting enables header injection, cache poisoning, and reflected XSS via crafted responses.',
    remediation: 'Encode/strip CRLF from any user input placed in response headers. Prefer framework redirect/cookie APIs that neutralize control characters. Validate redirect targets against an allowlist.',
  },
  directory_listing: {
    title: 'Directory Listing',
    description: 'Checks common directories for auto-index (directory listing) pages. An enabled listing exposes files not meant to be public — backups, configs, source, and other unreferenced content.',
    remediation: 'Disable auto-indexing (Apache: Options -Indexes; nginx: autoindex off). Place an index file in served directories and restrict access to non-public folders.',
  },
  js_enum: {
    title: 'JavaScript Secret Enumeration',
    description: 'Scans linked JavaScript for hard-coded secrets — API keys, tokens, cloud credentials, and internal endpoints. Secrets embedded in client-side JS are fully recoverable by any visitor.',
    remediation: 'Never ship secrets in client-side code. Move secrets server-side, proxy third-party calls through the backend, and rotate any exposed key immediately. Add secret scanning to CI.',
  },
  username_enum: {
    title: 'Username Enumeration',
    description: 'Tests login, password-reset, and signup forms for behaviour that reveals whether an account exists (differential responses or distinct error messages). Enables targeted credential stuffing and phishing.',
    remediation: 'Return an identical generic message, status code, and response size for every failed attempt. Use neutral wording for reset/signup and add consistent timing.',
  },
  captcha: {
    title: 'CAPTCHA Not Enabled',
    description: 'Checks authentication-related pages (login, reset, signup) for a CAPTCHA or equivalent bot-protection widget. Without one, forms are exposed to automated brute-force, credential stuffing, and mass registration.',
    remediation: 'Add a CAPTCHA (reCAPTCHA v3, hCaptcha, or Cloudflare Turnstile) to authentication forms, complemented by rate limiting and account lockout.',
  },
  unencrypted_communication: {
    title: 'Unencrypted Communication',
    description: 'Confirms the application is served over plain HTTP with no working HTTPS service. All traffic — including credentials and session tokens — is transmitted in cleartext and can be read or modified by any attacker on the network path (MITM).',
    remediation: 'Deploy a valid TLS certificate and serve the application over HTTPS. Redirect all HTTP to HTTPS with a 301 and enable HSTS (Strict-Transport-Security: max-age=31536000; includeSubDomains).',
  },
  cors: {
    title: 'Insecure CORS Configuration',
    description: 'Tests every discovered URL for a permissive or broken CORS policy. When the server reflects an attacker-controlled Origin into Access-Control-Allow-Origin and also sets Access-Control-Allow-Credentials: true, any website can read authenticated responses cross-origin.',
    remediation: 'Do not reflect the Origin header into Access-Control-Allow-Origin. Validate Origin against a strict allowlist of exact trusted origins, never trust \'null\', and only send Access-Control-Allow-Credentials: true for allowlisted origins (never with a wildcard).',
  },
}

// Backward-compatible title map (module -> friendly title).
export const TESTCASE_TITLES = Object.fromEntries(
  Object.entries(TESTCASE_INFO).map(([k, v]) => [k, v.title])
)

// Run order (matches ALL_MODULES on the backend). Used to enumerate every
// test case for a completed scan re-opened from History.
export const TESTCASE_ORDER = [
  'crossdomain', 'sitemap', 'robots', 'git_enum', 'headers', 'web_server',
  'clickjacking', 'error_exceptions', 'host_header', 'http_bypass', 'trace',
  'autocomplete', 'req_splitting', 'res_splitting', 'directory_listing',
  'js_enum', 'username_enum', 'captcha', 'unencrypted_communication', 'cors',
]

// A finding is a benign "…Not Vulnerable" marker (e.g. robots.txt found,
// CAPTCHA present) rather than a real vulnerability.
export const isBenignFinding = (f) =>
  (f?.title || '').toLowerCase().includes('not vulnerable')
