"""
JWT findings are split into individual test cases (build_jwt_findings).

Per-check severity: None Algorithm=Critical, Algorithm Swap / Empty / Altered
Signature=High, Token Expiration=Info. A passed/untested check becomes an Info
"— Not Vulnerable" marker so it still renders as its own test case.
"""

from backend.analysis.attach import build_jwt_findings, build_findings

SCAN_ID = "s"
_NAMES = ["None Algorithm", "Algorithm Swap", "Empty Signature", "Altered Signature"]


def _result(vuln_names=(), expiry_vuln=False):
    checks = [{"name": n, "vulnerable": n in vuln_names, "status_code": 200,
               "technique": "t", "detail": "d"} for n in _NAMES]
    return {"checks": checks, "expiry": {"vulnerable": expiry_vuln, "label": "x"},
            "target_url": "http://t"}


def _by_module(findings):
    return {f.module: f for f in findings}


def test_emits_five_test_cases():
    fs = build_jwt_findings(SCAN_ID, _result())
    assert {f.module for f in fs} == {
        "jwt_none", "jwt_alg_swap", "jwt_empty_sig", "jwt_altered_sig", "jwt_expiry"}


def test_none_algorithm_vulnerable_is_critical():
    m = _by_module(build_jwt_findings(SCAN_ID, _result(vuln_names=["None Algorithm"])))
    assert m["jwt_none"].severity.value == "critical"
    assert m["jwt_none"].cvss_score == 9.1
    assert "Not Vulnerable" not in m["jwt_none"].title


def test_signature_attack_vulnerable_is_high():
    m = _by_module(build_jwt_findings(SCAN_ID, _result(vuln_names=["Empty Signature"])))
    assert m["jwt_empty_sig"].severity.value == "high" and m["jwt_empty_sig"].cvss_score == 8.2
    # a passed check is an Info "Not Vulnerable" marker
    assert m["jwt_alg_swap"].severity.value == "info"
    assert "Not Vulnerable" in m["jwt_alg_swap"].title


def test_expiry_vulnerable_is_info_and_flagged():
    m = _by_module(build_jwt_findings(SCAN_ID, _result(expiry_vuln=True)))
    assert m["jwt_expiry"].severity.value == "info"
    assert "Not Vulnerable" not in m["jwt_expiry"].title


def test_all_clean_are_info_not_vulnerable():
    fs = build_jwt_findings(SCAN_ID, _result())
    assert all(f.severity.value == "info" for f in fs)
    assert all("Not Vulnerable" in f.title for f in fs)


def test_build_findings_dispatch_returns_list():
    assert len(build_findings("jwt", SCAN_ID, _result())) == 5


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    print("ok")
