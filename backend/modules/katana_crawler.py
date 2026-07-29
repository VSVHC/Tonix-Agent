"""
modules/katana_crawler.py
──────────────────────────
Katana web crawler integration.

Implements the full discovery pipeline:

    Target URL → Katana → Extract → Normalize → Scope filter →
    Deduplicate → Verify (httpx) → Return only verified URLs

Katana runs JS-aware (─jc + headless) because the real targets are SPAs
and API gateways whose routes/endpoints live inside JavaScript, not in the
initial HTML. Everything Katana emits is then normalized, scope-filtered,
de-duplicated and — critically — VERIFIED with httpx before it is returned.
A URL is never trusted just because Katana discovered it.

Windows compatibility:
  Uses subprocess.run() inside a thread executor instead of
  asyncio.create_subprocess_exec() — works on ALL Windows event loop types.

Output is stored in ScopeEnforcer.crawl_result as a CrawlResult object:
  all_urls   → verified in-scope HTML pages (+ api-subdomain pages)
  api_endpoints → verified URLs that look like API endpoints
  js_files   → verified .js resources
  forms      → verified pages likely to contain forms

If Katana is not installed or the crawl fails, KatanaCrawlError is raised
and the scan is stopped immediately.
"""

import asyncio
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
from backend.config import settings
from backend.models import CrawlResult
from backend.scope import ScopeEnforcer
from backend.logger import get_logger

log = get_logger(__name__)

# HTTP status codes that mean "this URL is a real / valid endpoint" → keep.
VERIFY_KEEP_STATUS = {
    200, 201, 204,            # success
    301, 302, 307, 308,       # redirects (the URL itself exists)
    401, 403, 405,            # exists but auth/method gated
}

# Content-Type values (already lower-cased, ;charset stripped) that confirm a
# response body is real JavaScript. A .js URL whose body is actually the HTML
# app shell (soft-404) has content-type text/html and is rejected.
_JS_CONTENT_TYPES = {
    "application/javascript", "text/javascript", "application/x-javascript",
    "application/ecmascript", "text/ecmascript", "application/mjs", "text/jsx",
    "application/json",   # some bundlers/CDNs serve module JSON manifests
}

# Content-Types that unambiguously mark an HTML document (i.e. the app shell,
# never a real .js resource).
_HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}

# How many bytes of each response body to sample when fingerprinting. Enough to
# tell an SPA shell apart from real JS / JSON / server-rendered content, small
# enough that large JS bundles are never fully downloaded.
_BODY_SAMPLE = 16_384


class _RespSig(NamedTuple):
    """Lightweight fingerprint of an HTTP response used for verification."""
    status:     int
    ctype:      str    # lower-cased content-type, parameters stripped
    body_hash:  str    # sha1 of the first _BODY_SAMPLE bytes
    looks_html: bool   # sampled body starts with '<' (html/xml document)


class _Soft404Baseline(NamedTuple):
    """
    Fingerprint of how the target answers a URL that certainly does not exist.
    Present only when the target uses catch-all / soft-404 routing (a random
    path returns a 'keep' status instead of 404). `stable` is True when two
    independent random paths return the identical body — the shell is
    deterministic, so a candidate whose body matches it can be confidently
    rejected. When False the shell varies per request (nonces/CSRF) and body
    comparison is unreliable, so only status/content-type signals are trusted.
    """
    status:     int
    ctype:      str
    body_hash:  str
    stable:     bool

# HTTP statuses that signal the request was blocked by bot protection
# (Akamai / Cloudflare / etc.) rather than answered — worth retrying with a
# different User-Agent.
_UA_BLOCK_STATUS = {403, 429, 503}

# Fallback User-Agents tried, in order, when the configured UA is blocked.
# Declared library/tool UAs come first: bot managers (Akamai, etc.) frequently
# allow honest, self-identifying clients while blocking a `Mozilla/5.0` string
# that claims to be a browser but fails browser fingerprinting. A real browser
# UA is the last resort for the opposite kind of site (one that blocks non-
# browsers outright).
_UA_FALLBACKS = (
    f"python-httpx/{httpx.__version__}",
    "curl/8.5.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
)

# Non-HTML resource extensions. `.js` is handled separately (kept, bucketed
# into js_files); the rest are dropped from the page/api buckets entirely.
_STATIC_EXTENSIONS = {
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map",
    ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mp3", ".webp", ".avif",
    ".txt", ".csv", ".yaml", ".yml",
}


class KatanaCrawlError(Exception):
    """Raised when Katana is not found or the crawl fails."""
    pass


class KatanaCrawler:
    """
    Runs Katana against the target, then normalizes / scopes / dedupes /
    verifies every discovered URL and returns a CrawlResult containing only
    verified, in-scope URLs.

    Usage (called from orchestrator before the module loop):
        crawler = KatanaCrawler(scope, client=httpx_client)
        crawl_result = await crawler.crawl()
        scope.crawl_result = crawl_result
    """

    def __init__(self, scope: ScopeEnforcer, client: httpx.AsyncClient | None = None) -> None:
        self.scope        = scope
        self._client      = client
        self._log         = get_logger("katana_crawler")
        self._ua_override = None   # set by _select_user_agent when default UA is blocked

    # ─────────────────────────────────────────────────────
    #  Public entry point
    # ─────────────────────────────────────────────────────

    async def crawl(self) -> CrawlResult:
        """Run the full discovery pipeline and return a CrawlResult."""
        self._check_katana_installed()

        # If the target's bot protection blocks our User-Agent, switch to one
        # that gets through — applied to httpx AND Katana — before anything else
        # runs, otherwise every fetch returns an Access-Denied page.
        await self._select_user_agent()

        tmp_dir     = Path(tempfile.gettempdir())
        output_file = tmp_dir / f"katana_{self.scope.target_host.replace(':', '_')}.jsonl"
        output_file.unlink(missing_ok=True)

        self._log.info("Starting Katana crawl → %s", self.scope.target_url)
        started_at = time.monotonic()

        # ── Stage 1: Katana (JS-aware, headless with graceful fallback) ──
        result = await self._run(self._build_command(output_file, headless=True))
        if result.returncode != 0 and self._is_headless_failure(result) \
                and settings.KATANA_HEADLESS:
            self._log.warning(
                "Headless Chrome unavailable — retrying without -headless "
                "(JS parsing still on). Install Chrome for full SPA coverage."
            )
            output_file.unlink(missing_ok=True)
            result = await self._run(self._build_command(output_file, headless=False))

        crawl_duration = time.monotonic() - started_at
        if result.returncode != 0:
            err_msg = (result.stderr or "").strip()
            raise KatanaCrawlError(
                f"Katana exited with code {result.returncode}.\n"
                f"stderr: {err_msg or '(empty)'}"
            )
        self._log.info("Katana finished in %.1fs", crawl_duration)

        # ── Stage 2: Extract raw URLs ──
        raw_urls = self._parse_output(output_file)
        self._log.info("Extracted %d raw URL(s) from Katana", len(raw_urls))

        # URLs that came from Katana's OWN crawl (real navigation / JS
        # route-table parsing / headless rendering) — highest confidence.
        # Anything added later by our own supplemental regex mining is NOT
        # in this set, and gets extra scrutiny in _verify_urls() on
        # catch-all/soft-404 targets (see that method's docstring).
        native_urls = {n for n in (self._normalize(u) for u in raw_urls) if n}

        # ── Stage 3-5: Normalize → scope filter → dedupe → classify ──
        result_cr = self._classify(raw_urls, crawl_duration)
        self._log.info(
            "After normalize/scope/dedupe — pages=%d js=%d api=%d",
            result_cr.url_count, result_cr.js_count, result_cr.api_count,
        )

        # ── Stage 5b: Supplemental discovery (Katana-independent) ──
        # Directly mine HTML pages and JS bundles for <script src>, <link
        # href>, <a href> and .js / API references. This catches the Vite
        # entry bundle, modulepreload chunks and route links that Katana's
        # crawl can miss on Laravel/Vite/SPA targets.
        #
        # `trusted_urls` = Katana-native routes ∪ routes the site declares about
        # itself (links in its HTML + route paths written into its own JS). On
        # catch-all / soft-404 targets these are kept even though they return the
        # same app shell as every path, because httpx cannot otherwise confirm a
        # client-side route — a route the site's own code declares is real. This
        # surfaces /about, /careers, /contact on a client-rendered SPA.
        trusted_urls = set(native_urls)
        if self._client:
            extra, declared = await self._supplement(result_cr)
            trusted_urls |= {n for n in (self._normalize(u) for u in declared) if n}
            if extra:
                self._log.info("Supplemental discovery added %d raw ref(s)", len(extra))
                result_cr = self._classify(raw_urls + extra, crawl_duration)
                self._log.info(
                    "After supplement — pages=%d js=%d api=%d",
                    result_cr.url_count, result_cr.js_count, result_cr.api_count,
                )

        # ── Stage 6: Verify every candidate with httpx ──
        if self._client:
            await self._verify_and_reconcile(result_cr, trusted_urls)

        self._log.info(
            "Verified crawl result — pages=%d js=%d api=%d forms=%d",
            result_cr.url_count, result_cr.js_count,
            result_cr.api_count, result_cr.form_count,
        )

        output_file.unlink(missing_ok=True)
        return result_cr

    # ─────────────────────────────────────────────────────
    #  Stage 1 — Katana subprocess
    # ─────────────────────────────────────────────────────

    def _build_command(self, output_file: Path, headless: bool) -> list[str]:
        """
        Build the Katana CLI command for JS-aware recursive crawling.

        -d <depth>  crawl deep enough to exhaust internal routes
        -jc         parse .js bundles for endpoints/routes/nested JS
        -headless   render client-side routes in real Chrome (auto-fallback)
        -kf all     also fetch robots.txt + sitemap.xml
        -fs <scope> rdn when any same-domain subdomain is allowed (so Katana can
                    discover asset./api./static.<domain>), otherwise fqdn (exact
                    host). Off-host noise is removed later by our scope filter.
        """
        allow_subdomains = (
            settings.SCOPE_ALLOW_SUBDOMAINS or settings.SCOPE_ALLOW_API_SUBDOMAIN
        )
        field_scope = "rdn" if allow_subdomains else "fqdn"

        cmd = [
            settings.KATANA_PATH,
            "-u",  self.scope.target_url,
            "-d",  str(settings.KATANA_DEPTH),
            "-c",  str(settings.KATANA_CONCURRENCY),
            "-o",  str(output_file),
            "-fs", field_scope,
            "-jsonl", "-silent", "-no-color",
        ]
        if settings.KATANA_KNOWN_FILES:
            cmd += ["-kf", settings.KATANA_KNOWN_FILES]
        if settings.KATANA_JS_CRAWL:
            cmd += ["-jc"]
        if headless and settings.KATANA_HEADLESS:
            cmd += ["-headless", "-no-sandbox"]
        if settings.KATANA_RATE_LIMIT and settings.KATANA_RATE_LIMIT > 0:
            cmd += ["-rl", str(settings.KATANA_RATE_LIMIT)]
        # Use the same non-blocked User-Agent httpx settled on (if any).
        if self._ua_override:
            cmd += ["-H", f"User-Agent: {self._ua_override}"]
        return cmd

    async def _select_user_agent(self) -> None:
        """
        Probe the target root. If the configured User-Agent is blocked by the
        target's bot protection (403/429/503), retry with the fallbacks and
        adopt the first that gets through — mutating the shared httpx client so
        every later request (supplement + verification) uses it, and recording
        it so `_build_command` passes it to Katana via -H. No-op when the
        default UA already works or when there is no client to probe with.
        """
        if not self._client:
            return

        async def status_for(ua: str | None) -> int | None:
            headers = {"User-Agent": ua} if ua else None
            try:
                r = await self._client.get(
                    self.scope.target_url, headers=headers, follow_redirects=True
                )
                return r.status_code
            except Exception:
                return None

        code = await status_for(None)
        if code is None or code not in _UA_BLOCK_STATUS:
            return   # default UA works (or a failure a UA swap can't fix)

        for ua in _UA_FALLBACKS:
            alt = await status_for(ua)
            if alt is not None and alt not in _UA_BLOCK_STATUS:
                self._client.headers["User-Agent"] = ua
                self._ua_override = ua
                self._log.warning(
                    "Target blocked the default User-Agent (HTTP %s); switched to "
                    "%r (HTTP %s) for httpx and Katana.", code, ua, alt,
                )
                return

        self._log.warning(
            "Target blocks every probe User-Agent (HTTP %s) — bot protection may "
            "limit discovery. Consider running Katana with headless Chrome.", code,
        )

    async def _run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        """Run one katana invocation in a thread executor.

        KATANA_TIMEOUT <= 0 means no wall-clock limit: katana runs until it has
        listed every URL within depth+scope (it terminates on its own).
        """
        self._log.debug("Command: %s", " ".join(cmd))
        loop = asyncio.get_event_loop()
        # ponytail: timeout<=0 disables the backstop; katana ends itself on a
        # depth-limited crawl. Set a positive KATANA_TIMEOUT to re-cap it.
        outer = None if settings.KATANA_TIMEOUT <= 0 else settings.KATANA_TIMEOUT + 5
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._run_katana_subprocess, cmd),
                timeout=outer,
            )
        except asyncio.TimeoutError:
            raise KatanaCrawlError(
                f"Katana crawl timed out after {settings.KATANA_TIMEOUT}s "
                f"on target {self.scope.target_url}"
            )

    @staticmethod
    def _is_headless_failure(result: subprocess.CompletedProcess) -> bool:
        """True when a non-zero exit was caused by missing/broken Chrome."""
        blob = ((result.stderr or "") + (result.stdout or "")).lower()
        hints = (
            "chrome", "chromium", "headless", "browser", "could not find",
            "executable", "no such file", "devtools", "failed to launch",
        )
        return any(h in blob for h in hints)

    def _run_katana_subprocess(self, cmd: list[str]) -> subprocess.CompletedProcess:
        """Blocking subprocess call — runs in a thread executor."""
        try:
            return subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=(settings.KATANA_TIMEOUT if settings.KATANA_TIMEOUT > 0 else None),
            )
        except FileNotFoundError:
            raise KatanaCrawlError(
                "Katana binary not found. "
                "Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"
            )
        except subprocess.TimeoutExpired:
            raise KatanaCrawlError(
                f"Katana timed out after {settings.KATANA_TIMEOUT}s "
                f"on target {self.scope.target_url}"
            )

    def _check_katana_installed(self) -> None:
        """Raise KatanaCrawlError early if katana binary is missing."""
        binary = shutil.which(settings.KATANA_PATH)
        if not binary:
            if sys.platform == "win32":
                import os
                go_bin = Path(os.environ.get("USERPROFILE", "")) / "go" / "bin" / "katana.exe"
                if go_bin.exists():
                    settings.KATANA_PATH = str(go_bin)
                    self._log.info("Katana found at: %s", go_bin)
                    return
            raise KatanaCrawlError(
                f"Katana not found at '{settings.KATANA_PATH}'.\n"
                "Install: go install github.com/projectdiscovery/katana/cmd/katana@latest\n"
                "Then add %USERPROFILE%\\go\\bin (or $HOME/go/bin) to PATH."
            )

    # ─────────────────────────────────────────────────────
    #  Stage 2 — Extract
    # ─────────────────────────────────────────────────────

    def _parse_output(self, output_file: Path) -> list[str]:
        """Parse Katana's JSONL output and return a flat list of raw URLs."""
        if not output_file.exists():
            self._log.warning("Katana output file not found: %s", output_file)
            return []

        urls: list[str] = []
        raw_text = output_file.read_text(encoding="utf-8", errors="replace")
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                url = (
                    obj.get("endpoint")
                    or obj.get("request", {}).get("endpoint")
                    or obj.get("url")
                    or ""
                )
                if url:
                    urls.append(url.strip())
            except (json.JSONDecodeError, AttributeError):
                if line.startswith(("http://", "https://")):
                    urls.append(line)
        return urls

    # ─────────────────────────────────────────────────────
    #  Stage 3 — Normalize
    # ─────────────────────────────────────────────────────

    @staticmethod
    def _normalize(url: str) -> str | None:
        """
        Canonicalise a URL so equivalent forms dedupe to one entry:
          - lowercase scheme + host
          - drop default ports (:80 http, :443 https)
          - collapse duplicate slashes in the path
          - strip trailing slash (except root)
          - drop the #fragment (keep the ?query)
        Returns None for non-http(s) URLs (mailto:, javascript:, tel:, …).
        """
        try:
            p = urlparse(url)
        except Exception:
            return None

        scheme = p.scheme.lower()
        if scheme not in ("http", "https"):
            return None

        host = (p.hostname or "").lower()
        if not host:
            return None

        port = p.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None
        netloc = f"{host}:{port}" if port else host

        path = re.sub(r"/{2,}", "/", p.path or "/")
        if len(path) > 1:
            path = path.rstrip("/")
        if not path:
            path = "/"

        return urlunparse((scheme, netloc, path, "", p.query, ""))

    @staticmethod
    def _looks_like_garbage(url: str) -> bool:
        """
        Detect malformed URLs that JavaScript parsing (-jc) can emit:
        unresolved template literals, wildcard/regex fragments, whitespace,
        or runaway matches that swallowed far more than a URL.
        """
        if not url or not url.startswith(("http://", "https://")):
            return True
        if len(url) > 300:   # a real URL is never this long — regex over-match
            return True
        bad_markers = ("${", "{{", "}}", "`", "<", ">", "*", "\\", " ", "\t")
        if any(m in url for m in bad_markers):
            return True
        try:
            path = urlparse(url).path
        except Exception:
            return True
        if "+" in path or "//" in path.lstrip("/"):
            return True
        return False

    # ─────────────────────────────────────────────────────
    #  Stages 4-5 — Scope filter + dedupe + classify
    # ─────────────────────────────────────────────────────

    def _is_api_url(self, host: str, path: str) -> bool:
        """Generic API detection: api./ host, or common API path shapes."""
        if host.startswith("api."):
            return True
        markers = (
            "/api", "/graphql", "/gql", "/rest", "/rpc", "/oauth",
            "/jsonrpc", "/wp-json",
        )
        if any(m == path or path.startswith(m + "/") or (m + "/") in path
               for m in markers):
            return True
        # versioned endpoints like /v1/…, /v2/…
        if re.match(r"^/v\d+(/|$)", path):
            return True
        return False

    def _classify(self, raw_urls: list[str], crawl_duration: float) -> CrawlResult:
        """Normalize → scope filter → dedupe → classify into typed buckets."""
        seen:          set[str]  = set()
        all_urls:      list[str] = []
        endpoints:     list[str] = []
        api_endpoints: list[str] = []
        forms:         list[str] = []
        js_files:      list[str] = []

        FORM_PATH_HINTS = {
            "login", "signin", "sign-in", "register", "signup", "sign-up",
            "checkout", "payment", "contact", "search", "forgot", "reset",
            "password", "subscribe", "feedback", "comment", "review",
            "upload", "submit", "apply", "enquiry", "inquiry", "profile",
            "account", "settings", "preferences", "auth",
        }
        ASSET_PATH_SEGMENTS = (
            "/static/", "/media/", "/images/", "/fonts/", "/uploads/", "/files/",
        )

        for raw in raw_urls:
            # ── Stage 3: normalize ──
            url = self._normalize(raw)
            if url is None or self._looks_like_garbage(url):
                continue

            # ── Stage 5: dedupe ──
            if url in seen:
                continue
            seen.add(url)

            # ── Stage 4: scope filter ──
            if not self.scope.is_in_scope(url):
                continue

            parsed = urlparse(url)
            host   = (parsed.hostname or "").lower()
            path   = parsed.path.lower() or "/"

            last_segment = path.split("/")[-1]
            dot          = last_segment.rfind(".")
            extension    = last_segment[dot:] if dot != -1 else ""

            # JS files → js_files bucket (kept + verified later)
            if extension == ".js":
                js_files.append(url)
                continue

            # Other static assets (css/img/font/…) → drop
            if extension in _STATIC_EXTENSIONS:
                continue

            # Asset folders that aren't JS → drop (not real pages)
            if any(seg in path for seg in ASSET_PATH_SEGMENTS):
                continue

            # Real page / endpoint
            all_urls.append(url)
            endpoints.append(parsed.path or "/")

            if self._is_api_url(host, path):
                api_endpoints.append(url)

            if set(path.strip("/").split("/")) & FORM_PATH_HINTS:
                forms.append(url)

        # Always include the target root
        root = self._normalize(self.scope.base_url + "/") or (self.scope.base_url + "/")
        if root not in seen:
            all_urls.insert(0, root)
            endpoints.insert(0, "/")
            seen.add(root)

        return CrawlResult(
            all_urls=all_urls,
            endpoints=list(dict.fromkeys(endpoints)),
            api_endpoints=list(dict.fromkeys(api_endpoints)),
            forms=list(dict.fromkeys(forms)),
            js_files=list(dict.fromkeys(js_files)),
            crawl_duration=crawl_duration,
        )

    # ─────────────────────────────────────────────────────
    #  Stage 5b — Supplemental discovery (mine HTML + JS)
    # ─────────────────────────────────────────────────────

    # <script src>, <link href>, <a href>, lazy data-src — any framework's HTML
    _ATTR_RE  = re.compile(r"""(?:src|href|data-src)\s*=\s*["']([^"'#\s]+)["']""", re.I)
    # Any ".js"/".mjs" string literal → catches every bundler's chunks
    # (Vite build/assets, Next _next/static/chunks, Webpack static/js,
    #  Angular main.<hash>.js, Nuxt _nuxt, Vue js/chunk-vendors, …)
    _JS_RE    = re.compile(r"""["'`]([^"'`\s<>]+?\.(?:js|mjs))(?:\?[^"'`]*)?["'`]""", re.I)
    # Same-host absolute URLs embedded anywhere in JS
    _URL_RE   = re.compile(r"""(https?://[A-Za-z0-9.\-]+(?::\d+)?/[^\s"'`<>()\\]*)""")
    # Quoted absolute paths (route tables, fetch() targets). The restrictive
    # char class already excludes JS regex literals, template exprs, etc.
    _PATHQ_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./%~:]{1,120})["'`]""")

    # Extensions that mean a quoted path is an asset, not an app route/endpoint.
    _NONROUTE_EXT = (
        ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".avif", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".json",
        ".xml", ".txt", ".mp4", ".mp3", ".pdf", ".wasm", ".html",
    )

    # A bare version number ("/1.2.3") or a long hex string ("/8f3a1c9b2e4d")
    # is almost always a semver tag or a bundler chunk hash picked up by the
    # freeform quoted-path regex (_PATHQ_RE) — not a real app route.
    _VERSION_SEGMENT_RE  = re.compile(r"^v?\d+(\.\d+){1,3}$")
    _HEX_HASH_SEGMENT_RE = re.compile(r"^[0-9a-f]{16,40}$", re.IGNORECASE)

    @classmethod
    def _looks_like_route(cls, path: str) -> bool:
        """Generic filter: keep app routes / API paths, drop asset & junk paths."""
        p = path.split("?")[0].lower()
        if len(p) < 2 or " " in p or p.startswith(("/./", "/../")):
            return False
        # Route *templates* with placeholders (":slug", "{id}", "*") are patterns
        # from the router config, not fetchable URLs — drop them.
        if any(c in p for c in (":", "{", "}", "*")):
            return False
        if any(p.endswith(ext) for ext in cls._NONROUTE_EXT):
            return False
        if not any(c.isalpha() for c in p):        # skip "/123", "/"
            return False
        segs = [s for s in p.strip("/").split("/") if s]
        if not segs:
            return False
        if len(segs) == 1:
            seg = segs[0]
            if len(seg) < 3:                        # skip "/g", "/rn" (regex-ish)
                return False
            if cls._VERSION_SEGMENT_RE.match(seg):   # skip "/1.2.3" (semver, not a route)
                return False
            if cls._HEX_HASH_SEGMENT_RE.match(seg):  # skip "/8f3a1c9b2e" (bundler chunk hash)
                return False
        return True

    async def _supplement(self, cr: CrawlResult) -> tuple[list[str], set[str]]:
        """
        Fetch discovered HTML pages and JS files and extract further URL
        references directly, so nothing depends on Katana emitting a
        <script type=module> / modulepreload / lazy-import it didn't follow.

        Works for any stack — the ".js" and href/src extraction is bundler-
        agnostic, and JS mining is iterative (HTML → entry bundle → chunks →
        nested chunks) until no new JS appears (bounded).

        Returns ``(found, declared)``:
          found    — flat list of every raw (absolute) URL reference, fed back
                     through the normalize/scope/dedupe/verify pipeline.
          declared — the subset the site declares about its OWN routes: links in
                     real server HTML (<a href>/src) plus route-shaped paths
                     written into the app's JavaScript (the SPA router config,
                     e.g. "/about-us", "/careers"). On catch-all / soft-404
                     targets every path returns the same app shell, so httpx
                     can't confirm a client-side route — but a route the site's
                     own code declares is real, so these are trusted like
                     Katana-native routes instead of being dropped. This is what
                     surfaces /about, /careers, /contact on a client-rendered SPA
                     whose homepage HTML is just an empty shell.
        """
        sem   = asyncio.Semaphore(settings.KATANA_VERIFY_CONCURRENCY)
        found:    set[str] = set()
        declared: set[str] = set()
        mined:    set[str] = set()
        app_origin = self.scope.base_url + "/"   # where app routes/APIs actually live
        # MAX_BYTES caps how much of each already-downloaded body we scan (it
        # does not limit the download). Modern SPA HTML loads its <script src>
        # bundles right before </body>, so an 800 KB cap silently dropped every
        # JS reference on large pages (nykaaman's homepage is ~900 KB). Scan up
        # to 5 MB so those trailing bundle tags — and endpoints in big vendor
        # bundles — are seen.
        MAX_PAGES, MAX_JS_TOTAL, MAX_BYTES, MAX_ROUNDS = 40, 80, 5_000_000, 4

        pages = list(dict.fromkeys(
            [self.scope.target_url, self.scope.base_url + "/"] + cr.all_urls
        ))[:MAX_PAGES]

        async def body(url: str) -> str | None:
            async with sem:
                try:
                    r = await self._client.get(url, follow_redirects=True)
                    if r.status_code >= 400:
                        return None
                    return r.text[:MAX_BYTES]
                except Exception:
                    return None

        async def mine_html(url: str) -> None:
            html = await body(url)
            if not html:
                return
            for ref in self._ATTR_RE.findall(html):
                absu = urljoin(url, ref)
                found.add(absu)
                declared.add(absu)   # came from real HTML markup → high confidence

        async def mine_js(url: str) -> None:
            code = await body(url)
            if not code:
                return
            for ref in self._JS_RE.findall(code):
                found.add(urljoin(url, ref))   # .js chunks live beside their parent bundle
            for ref in self._URL_RE.findall(code):
                found.add(ref)
            for ref in self._PATHQ_RE.findall(code):
                if self._looks_like_route(ref):
                    # A route/API path (e.g. "/api/v1/users") is an APPLICATION
                    # path. Resolve it against the target's own origin, NOT the
                    # host of the JS file — bundles are often served from a
                    # static-asset subdomain (asset.example.com) that never
                    # answers /api routes, which would make the endpoint 404 in
                    # verification and be lost. On same-host setups this is a
                    # no-op (the origins are identical).
                    absu = urljoin(app_origin, ref)
                    found.add(absu)
                    declared.add(absu)   # route path written in the app's own JS

        def pending_js() -> list[str]:
            """In-scope .js URLs discovered so far that we haven't mined yet."""
            out = []
            for u in list(found) + list(cr.js_files):
                n = self._normalize(u)
                if not n or n in mined:
                    continue
                if n.split("?")[0].lower().endswith((".js", ".mjs")) \
                        and self.scope.is_in_scope(n):
                    out.append(n)
            return out[:MAX_JS_TOTAL]

        # 1) Mine every HTML page once (finds the entry bundle + route links).
        await asyncio.gather(*[mine_html(u) for u in pages])

        # 2) Iteratively mine JS bundles → their chunks → those chunks' chunks.
        for _ in range(MAX_ROUNDS):
            todo = [u for u in pending_js() if u not in mined]
            if not todo:
                break
            mined.update(todo)
            await asyncio.gather(*[mine_js(u) for u in todo])

        return list(found), declared

    # ─────────────────────────────────────────────────────
    #  Stage 6 — httpx verification
    # ─────────────────────────────────────────────────────

    async def _verify_and_reconcile(
        self, cr: CrawlResult, trusted_urls: set[str]
    ) -> None:
        """
        Verify every candidate URL with httpx and drop anything that can't be
        confirmed to exist. Rebuilds all buckets so nothing references a
        discarded URL.

        `trusted_urls` are high-confidence routes: those Katana reached through
        its own crawl (real navigation / headless render / .js route-table
        parsing) plus those explicitly linked as an <a href>/src in the site's
        own HTML. Everything else was mined freeform out of a JS bundle and is
        treated as a guess: on catch-all / soft-404 targets (where httpx sees
        HTTP 200 for literally any path) those guesses are dropped unless their
        response is provably different from the app shell. This stops the crawl
        from reporting hundreds of non-existent pages and phantom .js files on
        SPA targets while still surfacing the site's real, linked routes.
        """
        candidates = list(dict.fromkeys(cr.all_urls + cr.js_files + cr.api_endpoints))

        # Fingerprint how the target answers a URL that certainly doesn't exist.
        baseline = await self._soft_404_baseline()

        verified = await self._verify_urls(candidates, trusted_urls, baseline)

        # The target root is always kept even if it momentarily fails.
        root = self._normalize(self.scope.base_url + "/") or (self.scope.base_url + "/")
        verified.add(root)

        cr.all_urls      = [u for u in cr.all_urls      if u in verified]
        cr.js_files      = [u for u in cr.js_files      if u in verified]
        cr.api_endpoints = [u for u in cr.api_endpoints if u in verified]
        cr.forms         = [u for u in cr.forms         if u in verified]
        cr.endpoints     = list(dict.fromkeys(
            (urlparse(u).path or "/") for u in cr.all_urls
        ))

    # ── Response fingerprinting ──────────────────────────────

    async def _signature(self, url: str) -> _RespSig | None:
        """
        GET `url` without following redirects and return a fingerprint of the
        response (status, content-type, hash + shape of a bounded body sample).
        Only the first _BODY_SAMPLE bytes are read — the connection is closed
        early, so large JS bundles are never fully downloaded. Returns None on
        any network / protocol error.
        """
        try:
            async with self._client.stream(
                "GET", url, follow_redirects=False
            ) as resp:
                status = resp.status_code
                ctype  = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                chunk  = bytearray()
                async for part in resp.aiter_bytes():
                    chunk.extend(part)
                    if len(chunk) >= _BODY_SAMPLE:
                        break
            body = bytes(chunk[:_BODY_SAMPLE])
            looks_html = body.lstrip()[:16].lstrip(b"\xef\xbb\xbf").startswith(b"<")
            return _RespSig(status, ctype, hashlib.sha1(body).hexdigest(), looks_html)
        except Exception:
            return None

    @staticmethod
    def _js_body_is_real(sig: _RespSig) -> bool:
        """
        True when a .js candidate's response is actually JavaScript and not the
        HTML app shell served for a non-existent path (the #1 source of phantom
        .js files on SPA targets).
        """
        if sig.ctype in _JS_CONTENT_TYPES:
            return True
        if sig.ctype in _HTML_CONTENT_TYPES or sig.looks_html:
            return False
        # Unlabelled / octet-stream body that isn't HTML → trust it as JS
        # (some static hosts serve .js as application/octet-stream).
        return True

    @staticmethod
    def _differs_from_shell(sig: _RespSig, base: _Soft404Baseline) -> bool:
        """
        On a catch-all target, decide whether `sig` is a real distinct resource
        rather than the same app shell returned for every unknown path.
        """
        if sig.status != base.status:
            return True
        # A non-HTML content-type (JSON, JS, XML, …) is real content the shell
        # would never return — e.g. a genuine API endpoint.
        if sig.ctype and sig.ctype not in _HTML_CONTENT_TYPES and sig.ctype != base.ctype:
            return True
        # Body comparison is only meaningful when the shell is deterministic.
        if base.stable and sig.body_hash != base.body_hash:
            return True
        return False

    async def _verify_urls(
        self,
        urls:         list[str],
        trusted_urls: set[str],
        baseline:     _Soft404Baseline | None,
    ) -> set[str]:
        """
        Verify every candidate and keep only those confirmed to exist:

          * status must be in VERIFY_KEEP_STATUS (404/410/5xx/errors dropped);
          * a .js URL must return a real JavaScript body (not the HTML shell);
          * on catch-all / soft-404 targets, a page/endpoint that is NOT trusted
            (neither Katana-native nor linked in the site's HTML) is kept only if
            its response is provably different from the app shell — otherwise
            it's an unverifiable guess and is dropped.

        On normal targets (real 404s, `baseline is None`) status is trusted, so
        behaviour is unchanged from a plain existence check.
        """
        sem = asyncio.Semaphore(settings.KATANA_VERIFY_CONCURRENCY)

        async def check(u: str) -> str | None:
            async with sem:
                sig = await self._signature(u)
                if sig is None or sig.status not in VERIFY_KEEP_STATUS:
                    return None

                is_js = u.split("?")[0].lower().endswith((".js", ".mjs"))
                if is_js:
                    return u if self._js_body_is_real(sig) else None

                # Page / API / endpoint.
                if baseline is None:
                    return u                      # server returns real 404s → status is trustworthy
                if u in trusted_urls:
                    return u                      # Katana-native or linked in HTML → real
                return u if self._differs_from_shell(sig, baseline) else None

        results  = await asyncio.gather(*[check(u) for u in urls])
        verified = {u for u in results if u is not None}
        self._log.info(
            "httpx verification — %d candidate(s) → %d verified%s",
            len(urls), len(verified),
            " (catch-all target: unconfirmable guesses dropped)" if baseline else "",
        )
        return verified

    async def _soft_404_baseline(self) -> _Soft404Baseline | None:
        """
        Probe two independent random paths. If the target returns a 'keep'
        status for a URL that cannot exist, it uses catch-all / soft-404
        routing (typical of SPAs, where every path yields the app shell) and we
        return a baseline fingerprint used to filter unconfirmable guesses.
        Returns None for well-behaved targets that answer non-existent paths
        with 404/410 — those need no special handling.
        """
        sigs: list[_RespSig | None] = []
        for _ in range(2):
            probe = f"{self.scope.base_url}/pentest-nonexistent-{uuid.uuid4().hex}"
            sigs.append(await self._signature(probe))

        if not all(s and s.status in VERIFY_KEEP_STATUS for s in sigs):
            return None   # real 404s → not a catch-all target

        first, second = sigs  # type: ignore[misc]
        stable = (first.body_hash == second.body_hash and first.status == second.status)
        self._log.warning(
            "Target uses catch-all / soft-404 routing (random paths returned "
            "HTTP %d, shell %s). Regex-mined pages that can't be told apart "
            "from the app shell will be dropped; Katana-discovered routes and "
            "real JS/API responses are kept.",
            first.status, "stable" if stable else "varies per request",
        )
        return _Soft404Baseline(first.status, first.ctype, first.body_hash, stable)
