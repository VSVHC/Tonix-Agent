"""
backend/reports/build.py
────────────────────────
On-demand report builder. Generates a scan's PDF or HTML report from its
stored findings into a throwaway temp directory, for streaming download.

Nothing is persisted on disk — the download endpoint streams the file and
deletes the temp dir afterward (see /api/report in main.py).

Note: the live-scan status_map (which marks errored modules as
'not_applicable') only exists during the scan, so on-demand reports show those
modules as 'not_vulnerable' instead. Acceptable — findings are unchanged.
"""

from __future__ import annotations

import asyncio
import tempfile

from backend.reports.pdf_generator import generate_pdf_report, _clean_host
from backend.reports.html_report import generate_html_report
from backend.database.db import (
    get_scan_by_id, get_findings_by_scan, deduplicate_findings,
)

_GENERATORS = {"pdf": generate_pdf_report, "html": generate_html_report}


def count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if "not vulnerable" in (f.get("title") or "").lower():
            continue   # benign markers are not findings
        sev = (f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
    counts["total"] = sum(counts.values())
    return counts


async def build_report(scan_id: str, fmt: str) -> tuple[str, str]:
    """
    Build a report for `scan_id` in `fmt` ('pdf' | 'html').
    Returns (temp_dir, file_path); the caller is responsible for deleting
    temp_dir once the file has been streamed.
    """
    scan = await get_scan_by_id(scan_id)
    if not scan:
        raise ValueError("Scan not found")

    findings = await get_findings_by_scan(scan_id)
    deduped  = await deduplicate_findings(findings)
    counts   = count_by_severity(deduped)
    target_url = scan["target_url"]

    tmp_dir = tempfile.mkdtemp(prefix="tonix_report_")
    base    = f"{_clean_host(target_url)}_{scan_id[:8]}"
    path = await asyncio.to_thread(
        _GENERATORS[fmt],
        scan_id=scan_id, target_url=target_url, findings=deduped,
        counts=counts, filename=f"{base}.{fmt}", save_path=tmp_dir,
        ai_summary=scan.get("ai_summary") or "",
        ai_correlations=scan.get("ai_correlations") or [],
    )
    return tmp_dir, path
