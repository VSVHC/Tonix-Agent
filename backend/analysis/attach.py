"""
backend/analysis/attach.py
──────────────────────────
Convert a manual JWT tool result into scan Finding(s) so they can be attached
to a scan's report (Option A). Each finding's ``module`` matches a manual catalog
entry in reports/catalog.py, which the report renders only when such a finding is
present.

JWT is split into ONE finding per check — None Algorithm, Algorithm Swap, Empty
Signature, Altered Signature and Token Expiration — so each appears as its own
test case in the report with its own severity.
"""

from __future__ import annotations

from backend.models import Finding, Severity
from backend.reports.catalog import BY_NAME

# JWT check name (from jwt_tool) → its catalog / module name.
_JWT_CHECK_MODULE = {
    "None Algorithm":    "jwt_none",
    "Algorithm Swap":    "jwt_alg_swap",
    "Empty Signature":   "jwt_empty_sig",
    "Altered Signature": "jwt_altered_sig",
}


def _jwt_case_finding(scan_id: str, module: str, vulnerable: bool, tested: bool,
                      technique: str, detail: str, request_data: str,
                      response_data: str, target: str) -> Finding:
    """One JWT sub-test-case finding. Severity comes from its catalog entry when
    vulnerable; a passed/untested check becomes an Info 'Not Vulnerable' marker."""
    tc    = BY_NAME.get(module, {})
    title = tc.get("title", module)
    band  = (tc.get("severity") or "info").upper()

    if vulnerable:
        severity    = Severity(tc.get("severity", "info"))
        cvss_score  = tc.get("cvss_score")
        cvss_vector = tc.get("cvss_vector", "")
        state       = "VULNERABLE"
    else:
        title      += " — Not Vulnerable"
        severity    = Severity.INFO
        cvss_score  = None
        cvss_vector = ""
        state       = "SAFE" if tested else "NOT TESTED"

    evidence = f"{tc.get('title', module)} [{band}]: {state} — {technique}\n{detail}"

    return Finding(
        scan_id=scan_id, module=module, title=title, severity=severity,
        description=tc.get("description", ""), evidence=evidence,
        affected_urls=[target] if target else [],
        request_data=request_data, response_data=response_data,
        remediation=tc.get("remediation", ""),
        cvss_score=cvss_score, cvss_vector=cvss_vector,
    )


def build_jwt_findings(scan_id: str, result: dict) -> list[Finding]:
    """One finding per JWT check (4 forged-token replays + token expiration)."""
    checks  = result.get("checks", []) or []
    expiry  = result.get("expiry", {}) or {}
    target  = result.get("target_url") or ""
    by_name = {c.get("name"): c for c in checks}

    findings: list[Finding] = []
    for check_name, module in _JWT_CHECK_MODULE.items():
        c = by_name.get(check_name, {})
        findings.append(_jwt_case_finding(
            scan_id, module,
            vulnerable=bool(c.get("vulnerable")),
            tested=c.get("status_code") is not None,
            technique=c.get("technique", ""),
            detail=c.get("detail", ""),
            request_data=c.get("request_data", ""),
            response_data=c.get("response_data", ""),
            target=target,
        ))

    # Token expiration (always Info; "vulnerable" = excessive lifetime).
    exp_vuln = bool(expiry.get("vulnerable"))
    tc = BY_NAME.get("jwt_expiry", {})
    title = tc.get("title", "JWT — Token Expiration")
    if not exp_vuln:
        title += " — Not Vulnerable"
    evidence = (
        f"Token Expiration [INFO]: {'VULNERABLE' if exp_vuln else 'SAFE'} — {expiry.get('label', '')}\n"
        f"iat (UTC): {expiry.get('iat_human', '')}\nexp (UTC): {expiry.get('exp_human', '')}"
    )
    findings.append(Finding(
        scan_id=scan_id, module="jwt_expiry", title=title, severity=Severity.INFO,
        description=tc.get("description", ""), evidence=evidence,
        affected_urls=[target] if target else [],
        remediation=tc.get("remediation", ""),
        cvss_score=(tc.get("cvss_score") if exp_vuln else None),
        cvss_vector=(tc.get("cvss_vector", "") if exp_vuln else ""),
    ))
    return findings


def build_findings(tool: str, scan_id: str, result: dict) -> list[Finding]:
    """Return the finding(s) for a manual tool result (JWT → one per check)."""
    if tool == "jwt":
        return build_jwt_findings(scan_id, result)
    raise ValueError("tool must be 'jwt'")
