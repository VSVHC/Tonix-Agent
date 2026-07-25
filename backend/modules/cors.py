"""
modules/cors.py
────────────────
Testcase: Insecure CORS Configuration  (Katana-aware)

Tests every Katana-discovered URL for a permissive or broken Cross-Origin
Resource Sharing (CORS) policy. The classic critical bug: the server reflects
an attacker-controlled Origin into the Access-Control-Allow-Origin response
header AND sets Access-Control-Allow-Credentials: true — letting any website
read authenticated responses cross-origin (cross-site data theft).

Per URL (a GET carrying an injected Origin header, redirects NOT followed):
  1. Reflection    — an attacker origin is echoed back in ACAO
  2. Null origin   — Origin: null is trusted
  3. Suffix bypass — https://<target-host>.attacker.tld is trusted (broken
                     origin validation)
  4. Wildcard      — Access-Control-Allow-Origin: *  (severity by credentials)

A URL is flagged only when the server reflects an origin WE control that is
clearly unrelated to the target, so an endpoint that ignores Origin or returns
its own fixed domain is correctly reported as Not Vulnerable.

Scope: API endpoints are tested first, then other pages, capped at MAX_URLS
and probed with bounded concurrency so large sites stay stable.
"""

import asyncio
import secrets
import httpx

from backend.modules.base_module import BaseModule
from backend.models import Finding

MAX_URLS    = 40   # cap probed URLs (API endpoints prioritised)
CONCURRENCY = 10   # simultaneous URL probes

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class CorsModule(BaseModule):
    name = "cors"

    def _urls(self) -> list[str]:
        """Katana URLs with API endpoints first; fall back to the root."""
        cr = self.scope.crawl_result
        if cr and cr.all_urls:
            api    = list(cr.api_endpoints or [])
            api_set = set(api)
            others = [u for u in cr.all_urls if u not in api_set]
            return list(dict.fromkeys(api + others))[:MAX_URLS]
        return [self.scope.base_url + "/"]

    async def run(self) -> list[Finding]:
        rid    = secrets.token_hex(4)
        host   = self.scope.target_host
        evil   = f"https://cors-probe-{rid}.attacker-test.com"
        suffix = f"https://{host}.attacker-{rid}.com"

        sem: asyncio.Semaphore = asyncio.Semaphore(CONCURRENCY)
        issues: list[dict] = []

        async def get(url: str, origin: str) -> httpx.Response | None:
            try:
                return await self._client.get(
                    url, headers={"Origin": origin}, follow_redirects=False
                )
            except httpx.RequestError:
                return None

        async def probe(url: str) -> None:
            if not self.scope.is_in_scope(url):
                return
            async with sem:
                # 1) Reflection probe (also catches wildcard).
                r = await get(url, evil)
                if r is None:
                    return
                acao = (r.headers.get("access-control-allow-origin") or "").strip()
                acac = (r.headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
                vary = (r.headers.get("vary") or "").lower()

                hit = _classify("reflection", evil, acao, acac)
                if hit:
                    issues.append(_issue(hit, url, evil, acao, acac))
                    return

                # If the endpoint neither returned a CORS header nor varies by
                # Origin, it doesn't process Origin at all → nothing to test.
                if not acao and "origin" not in vary:
                    return

                # 2) Null-origin probe.
                r = await get(url, "null")
                if r is not None:
                    acao = (r.headers.get("access-control-allow-origin") or "").strip()
                    acac = (r.headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
                    hit = _classify("null", "null", acao, acac)
                    if hit:
                        issues.append(_issue(hit, url, "null", acao, acac))
                        return

                # 3) Suffix / broken-validation probe.
                r = await get(url, suffix)
                if r is not None:
                    acao = (r.headers.get("access-control-allow-origin") or "").strip()
                    acac = (r.headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
                    hit = _classify("suffix", suffix, acao, acac)
                    if hit:
                        issues.append(_issue(hit, url, suffix, acao, acac))

        _urls = self._urls()
        _done = 0
        async def _probe_track(u):
            nonlocal _done
            await probe(u)
            _done += 1
            await self.report_progress(_done, len(_urls))
        await asyncio.gather(*[_probe_track(u) for u in _urls])

        if not issues:
            return []

        issues.sort(key=lambda i: _SEV_ORDER.get(i["severity"], 4))
        worst    = issues[0]["severity"]
        affected = list(dict.fromkeys(i["url"] for i in issues))
        creds_theft = any(i["acac"] and i["severity"] in ("critical", "high") for i in issues)

        evidence = "\n\n".join(
            f"URL: {i['url']}\n"
            f"Issue: {i['reason']}\n"
            f"Sent Origin: {i['origin']}\n"
            f"Access-Control-Allow-Origin: {i['acao'] or '(none)'}\n"
            f"Access-Control-Allow-Credentials: {str(i['acac']).lower()}"
            for i in issues[:15]
        )
        if len(issues) > 15:
            evidence += f"\n\n…and {len(issues) - 15} more."

        return [self.make_finding(
            title="Insecure CORS Configuration",
            # ponytail: company scheme fixes CORS at Low regardless of the
            # graduated `worst` classification (still used above for creds_theft
            # wording and evidence ordering).
            severity="low",
            description=(
                f"{len(affected)} endpoint(s) return a permissive or broken CORS policy. "
                "The server trusts an attacker-controlled Origin in its "
                "Access-Control-Allow-Origin response header"
                + (", combined with Access-Control-Allow-Credentials: true — allowing any "
                   "website to read authenticated responses cross-origin (cross-site data theft)."
                   if creds_theft else
                   ", allowing other origins to read its responses cross-origin.")
            ),
            evidence=evidence,
            affected_urls=affected,
            request_data=(
                f"GET {affected[0]} HTTP/1.1\n"
                f"Host: {host}\n"
                f"Origin: {issues[0]['origin']}"
            ),
            response_data=(
                f"Access-Control-Allow-Origin: {issues[0]['acao'] or '(none)'}\n"
                f"Access-Control-Allow-Credentials: {str(issues[0]['acac']).lower()}"
            ),
            remediation=(
                "Do not reflect the Origin header into Access-Control-Allow-Origin. "
                "Validate Origin against a strict allowlist of exact trusted origins. "
                "Never trust the 'null' origin. Only send "
                "Access-Control-Allow-Credentials: true for specifically allowlisted "
                "origins, and never together with a wildcard. Omit CORS headers entirely "
                "for endpoints that do not need cross-origin access."
            ),
        )]


# ─────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────

def _issue(hit: dict, url: str, origin: str, acao: str, acac: bool) -> dict:
    return {**hit, "url": url, "origin": origin, "acao": acao, "acac": acac}


def _classify(kind: str, origin: str, acao: str, acac: bool) -> dict | None:
    """Map a probe result to a severity + reason, or None if safe."""
    if kind == "reflection" and acao == origin:
        if acac:
            return {"severity": "critical", "reason": "Attacker origin reflected with credentials allowed"}
        return {"severity": "medium", "reason": "Attacker origin reflected (no credentials)"}
    if kind == "null" and acao.lower() == "null":
        return {"severity": "high" if acac else "medium", "reason": "Null origin trusted"}
    if kind == "suffix" and acao == origin:
        return {"severity": "high" if acac else "medium",
                "reason": "Broken origin validation — attacker subdomain/suffix trusted"}
    # Wildcard is only meaningful on the first (reflection) probe.
    if kind == "reflection" and acao == "*":
        return {"severity": "medium" if acac else "low", "reason": "Wildcard Access-Control-Allow-Origin"}
    return None
