"""
reports/pdf_generator.py
────────────────────────
Generates the downloadable PDF security assessment report using reportlab
(pure-Python, no native dependencies — reliable on Windows).

Structure (mirrors the approved reference layout):
  1. Cover page      — title, target, date/time, confidential notice
  2. Table of Contents — ID / Test Case / Module / Status / Severity + totals
  3. One section per test case (VULNERABLE, NOT VULNERABLE, NOT APPLICABLE):
       Title · Description · Severity · CVSS Score · Vulnerable Locations ·
       Parameters · Reference links · Reproduction Steps · Remediation ·
       Sample Code (N/A) · Proof of Concept (request/response; Images: N/A)

Every catalogued test case is rendered whether or not it produced a finding.
"""

from __future__ import annotations

import html
from pathlib import Path
from datetime import datetime, timezone

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    HRFlowable, ListFlowable, ListItem, Preformatted,
)

from backend.config import settings
from backend.reports.catalog import TEST_CASES, MANUAL_TEST_CASES, cvss_band

# ── Palette (matches the app's professional-blue theme) ──
BLUE       = colors.HexColor("#2563eb")
INK        = colors.HexColor("#101828")
SUBTLE     = colors.HexColor("#475467")
FAINT      = colors.HexColor("#98a2b3")
LINE       = colors.HexColor("#e4e7ec")
PANEL      = colors.HexColor("#f6f7f9")
CODE_BG    = colors.HexColor("#f1f3f6")

SEV_COLOR = {
    "critical": colors.HexColor("#b42318"),
    "high":     colors.HexColor("#b93815"),
    "medium":   colors.HexColor("#854a0e"),
    "low":      colors.HexColor("#067647"),
    "info":     colors.HexColor("#175cd3"),
    "na":       FAINT,
}
STATUS_COLOR = {
    "vulnerable":     colors.HexColor("#b42318"),
    "not_vulnerable": colors.HexColor("#067647"),
    "not_applicable": FAINT,
}
STATUS_LABEL = {
    "vulnerable": "VULNERABLE",
    "not_vulnerable": "NOT VULNERABLE",
    "not_applicable": "NOT APPLICABLE",
}


# ─────────────────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────────────────

def generate_pdf_report(
    scan_id: str,
    target_url: str,
    findings: list[dict],
    counts: dict,
    status_map: dict[str, str] | None = None,
    save_path: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    filename: str | None = None,
) -> str:
    """Render the PDF and return its absolute path."""
    host      = _clean_host(target_url)
    stamp     = datetime.now(timezone.utc)
    filename  = filename or f"{host}_{stamp.strftime('%Y-%m-%d_%H-%M')}.pdf"
    base_dir  = Path(save_path).expanduser().resolve() if save_path else settings.REPORTS_DIR
    base_dir.mkdir(parents=True, exist_ok=True)
    report_path = base_dir / filename

    results = _build_results(findings, status_map)

    doc = SimpleDocTemplate(
        str(report_path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"Security Assessment Report — {target_url}",
        author="Tonix Agent",
    )
    styles = _styles()
    story: list = []

    _cover(story, styles, target_url, stamp)
    _toc(story, styles, results)
    for r in results:
        _section(story, styles, r, target_url)

    doc.build(
        story,
        onFirstPage=lambda c, d: _decorate(c, d, target_url, cover=True),
        onLaterPages=lambda c, d: _decorate(c, d, target_url, cover=False),
    )
    return str(report_path)


# ─────────────────────────────────────────────────────────
#  Result assembly
# ─────────────────────────────────────────────────────────

def _build_results(findings: list[dict], status_map: dict[str, str] | None) -> list[dict]:
    """Attach each catalogued test case to its live status + findings."""
    grouped: dict[str, list[dict]] = {}
    for f in findings or []:
        grouped.setdefault(f.get("module", ""), []).append(f)

    # Automated cases always render; manual (JWT) cases render only when the
    # user attached a result for them to this scan.
    used_manual = [tc for tc in MANUAL_TEST_CASES if grouped.get(tc["name"])]
    all_cases = TEST_CASES + used_manual

    results = []
    for tc in all_cases:
        mod    = tc["name"]
        mfind  = grouped.get(mod, [])
        # A benign "…Not Vulnerable" marker (e.g. captcha present) is not a vuln.
        real   = [f for f in mfind if "not vulnerable" not in (f.get("title") or "").lower()]

        declared = (status_map or {}).get(mod)
        if declared == "not_applicable":
            status = "not_applicable"
        elif real:
            status = "vulnerable"
        else:
            status = "not_vulnerable"

        # Effective severity: worst live finding, else catalog band when clean.
        # CVSS follows the same worst finding — if it carries its own score
        # (impact-based modules), show that; otherwise fall back to the catalog.
        cvss_score  = tc["cvss_score"]
        cvss_vector = tc["cvss_vector"]
        if real:
            worst = min(real, key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 4))
            sev   = worst.get("severity", "info")
            if worst.get("cvss_score") is not None:
                cvss_score  = worst["cvss_score"]
                cvss_vector = worst.get("cvss_vector") or cvss_vector
        else:
            sev = None

        # Proof-of-concept source: a real finding when vulnerable, otherwise the
        # benign "Not Vulnerable" marker — which now carries the real captured
        # request/response so passed test cases show the same PoC as vulns.
        benign = [f for f in mfind if f not in real]
        poc    = real[0] if real else (benign[0] if benign else None)

        results.append({
            "tc": tc, "status": status, "findings": real, "severity": sev, "poc": poc,
            "cvss_score": cvss_score, "cvss_vector": cvss_vector,
        })
    return results


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ─────────────────────────────────────────────────────────
#  Cover
# ─────────────────────────────────────────────────────────

def _cover(story, S, target_url, stamp):
    story.append(Spacer(1, 55 * mm))
    story.append(Paragraph("Web Application", S["CoverTitle"]))
    story.append(Paragraph("Security Assessment Report", S["CoverTitle"]))
    story.append(Spacer(1, 10 * mm))
    story.append(HRFlowable(width="30%", thickness=2, color=BLUE, hAlign="CENTER"))
    story.append(Spacer(1, 14 * mm))

    meta = [
        ["TARGET URL", target_url],
        ["DATE", stamp.strftime("%B %d, %Y")],
        ["TIME", stamp.strftime("%I:%M %p UTC")],
    ]
    t = Table(meta, colWidths=[35 * mm, 120 * mm], hAlign="CENTER")
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), FAINT),
        ("TEXTCOLOR", (1, 0), (1, -1), INK),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
    ]))
    story.append(t)
    story.append(Spacer(1, 45 * mm))
    story.append(Paragraph(
        "CONFIDENTIAL — This report is intended solely for authorized recipients. "
        "Unauthorized disclosure, copying, or distribution is strictly prohibited.",
        S["Confidential"]))
    story.append(PageBreak())


# ─────────────────────────────────────────────────────────
#  Table of contents
# ─────────────────────────────────────────────────────────

def _toc(story, S, results):
    story.append(Paragraph("Table of Contents", S["H1"]))
    story.append(Spacer(1, 4 * mm))

    header = ["ID", "Test Case", "Module", "Status", "Severity"]
    rows = [header]
    for r in results:
        tc = r["tc"]
        sev = (r["severity"] or "—")
        rows.append([
            tc["id"], tc["title"], tc["module"],
            STATUS_LABEL[r["status"]],
            sev.upper() if sev != "—" else "—",
        ])

    t = Table(rows, colWidths=[15 * mm, 55 * mm, 49 * mm, 35 * mm, 20 * mm], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 1), (-1, -1), INK),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]),
    ]
    for i, r in enumerate(results, start=1):
        style.append(("TEXTCOLOR", (3, i), (3, i), STATUS_COLOR[r["status"]]))
        style.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))
        sev = r["severity"]
        if sev:
            style.append(("TEXTCOLOR", (4, i), (4, i), SEV_COLOR.get(sev, FAINT)))
            style.append(("FONTNAME", (4, i), (4, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    story.append(t)

    # Totals
    vuln = sum(1 for r in results if r["status"] == "vulnerable")
    nvul = sum(1 for r in results if r["status"] == "not_vulnerable")
    na   = sum(1 for r in results if r["status"] == "not_applicable")
    story.append(Spacer(1, 6 * mm))
    totals = Table(
        [["Vulnerable", str(vuln), "Not Vulnerable", str(nvul),
          "Not Applicable", str(na), "Total", str(len(results))]],
        colWidths=[26 * mm, 12 * mm, 30 * mm, 12 * mm, 30 * mm, 12 * mm, 16 * mm, 12 * mm],
        hAlign="LEFT",
    )
    totals.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
        ("TEXTCOLOR", (1, 0), (1, 0), STATUS_COLOR["vulnerable"]),
        ("FONTNAME", (3, 0), (3, 0), "Helvetica-Bold"),
        ("TEXTCOLOR", (3, 0), (3, 0), STATUS_COLOR["not_vulnerable"]),
        ("FONTNAME", (5, 0), (5, 0), "Helvetica-Bold"),
        ("FONTNAME", (7, 0), (7, 0), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, 0), SUBTLE),
        ("TEXTCOLOR", (2, 0), (2, 0), SUBTLE),
        ("TEXTCOLOR", (4, 0), (4, 0), SUBTLE),
        ("TEXTCOLOR", (6, 0), (6, 0), SUBTLE),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(totals)
    story.append(PageBreak())


# ─────────────────────────────────────────────────────────
#  Per-test-case section
# ─────────────────────────────────────────────────────────

def _section(story, S, r, target_url):
    tc     = r["tc"]
    status = r["status"]
    sev    = r["severity"]

    # ── Section header band ──
    story.append(Paragraph(f"TEST CASE · {tc['id']}", S["Eyebrow"]))
    story.append(Paragraph(esc(tc["title"]), S["H1"]))

    head = Table(
        [[Paragraph(f"<b>Module:</b> {esc(tc['module'])}", S["Meta"]),
          Paragraph(f'<b>Status:</b> <font color="#{STATUS_COLOR[status].hexval()[2:]}">'
                    f'{STATUS_LABEL[status]}</font>', S["Meta"])]],
        colWidths=[95 * mm, 74 * mm],
    )
    head.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.6, LINE),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(head)
    story.append(Spacer(1, 4 * mm))

    # ── Title / Description ──
    _field(story, S, "Description", esc(tc["description"]))

    # ── Severity + CVSS ──
    r_cvss, r_vec = r["cvss_score"], r["cvss_vector"]
    if status == "vulnerable":
        sev_txt  = f'<font color="#{SEV_COLOR.get(sev, FAINT).hexval()[2:]}"><b>{(sev or "").upper()}</b></font>'
        cvss_txt = f"<b>{r_cvss}</b> ({cvss_band(r_cvss).title()}) — {esc(r_vec)}"
    else:
        sev_txt  = ("Not Vulnerable" if status == "not_vulnerable" else "Not Applicable")
        cvss_txt = "N/A"
    _field(story, S, "Severity", sev_txt)
    _field(story, S, "CVSS Score", cvss_txt)

    # ── Vulnerable Locations ──
    urls = []
    for f in r["findings"]:
        for u in (f.get("affected_urls") or []):
            if u not in urls:
                urls.append(u)
    if urls:
        loc = "<br/>".join(f"• {esc(u)}" for u in urls[:40])
        if len(urls) > 40:
            loc += f"<br/>… and {len(urls) - 40} more"
    else:
        loc = "None — the target is not vulnerable to this test case." if status == "not_vulnerable" \
              else ("Not applicable." if status == "not_applicable" else "—")
    _field(story, S, "Vulnerable Locations", loc, mono=bool(urls))

    # ── Parameters ──
    _field(story, S, "Parameters", esc(tc["parameters"]))

    # ── Reference links ──
    refs = "<br/>".join(f"• {_linkify(x)}" for x in tc["references"])
    _field(story, S, "Reference Links", refs)

    # ── Reproduction steps ──
    story.append(Paragraph("Reproduction Steps", S["FieldLabel"]))
    steps = ListFlowable(
        [ListItem(Paragraph(esc(s), S["Body"]), leftIndent=6) for s in tc["reproduction"]],
        bulletType="1", bulletFontName="Helvetica-Bold", bulletColor=BLUE,
        leftIndent=14,
    )
    story.append(steps)
    story.append(Spacer(1, 4 * mm))

    # ── Remediation ──
    _callout(story, S, "Remediation", esc(tc["remediation"]))

    # ── Sample Code ──
    _field(story, S, "Sample Code", "N/A")

    # ── Proof of Concept ──
    story.append(Paragraph("Proof of Concept", S["FieldLabel"]))
    if r.get("poc"):
        f0 = r["poc"]
        if f0.get("evidence"):
            story.append(Paragraph("Evidence", S["SubLabel"]))
            story.append(_code(f0["evidence"]))
        if f0.get("request_data"):
            story.append(Paragraph("Request", S["SubLabel"]))
            story.append(_code(f0["request_data"]))
        if f0.get("response_data"):
            story.append(Paragraph("Response", S["SubLabel"]))
            story.append(_code(f0["response_data"]))
    else:
        story.append(Paragraph("No proof-of-concept captured — target not vulnerable to this test case."
                               if status == "not_vulnerable" else
                               "Not applicable — test case did not execute.", S["Body"]))
    story.append(Paragraph("PoC Images: N/A (automated assessment — no screenshots captured).", S["Note"]))

    story.append(PageBreak())


# ─────────────────────────────────────────────────────────
#  Field / callout / code helpers
# ─────────────────────────────────────────────────────────

def _field(story, S, label, value, mono=False):
    story.append(Paragraph(label, S["FieldLabel"]))
    story.append(Paragraph(value, S["Mono"] if mono else S["Body"]))
    story.append(Spacer(1, 3 * mm))


def _callout(story, S, label, value):
    story.append(Paragraph(label, S["FieldLabel"]))
    box = Table([[Paragraph(value, S["Body"])]], colWidths=[169 * mm])
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ecfdf3")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#abefc6")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(box)
    story.append(Spacer(1, 3 * mm))


def _code(text: str, limit: int = 1600) -> Table:
    text = (text or "")[:limit]
    wrapped = _wrap_code(text, width=96)
    pre = Preformatted(wrapped, ParagraphStyle(
        "code", fontName="Courier", fontSize=7.6, leading=9.6, textColor=INK,
    ))
    box = Table([[pre]], colWidths=[169 * mm])
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return box


def _wrap_code(text: str, width: int) -> str:
    out = []
    for line in text.replace("\t", "    ").splitlines() or [""]:
        while len(line) > width:
            out.append(line[:width])
            line = line[width:]
        out.append(line)
    return "\n".join(out)


def esc(s: str) -> str:
    return html.escape(str(s or ""))


def _linkify(ref: str) -> str:
    """Render a 'Text: URL' reference with the URL as a live blue link."""
    if ": http" in ref:
        label, url = ref.rsplit(": ", 1)
        return f'{esc(label)}: <link href="{esc(url)}"><font color="#2563eb">{esc(url)}</font></link>'
    if ref.startswith("http"):
        return f'<link href="{esc(ref)}"><font color="#2563eb">{esc(ref)}</font></link>'
    return esc(ref)


# ─────────────────────────────────────────────────────────
#  Styles + page decoration
# ─────────────────────────────────────────────────────────

def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("CoverTitle", parent=ss["Title"], fontSize=26, leading=30,
                          alignment=TA_CENTER, textColor=INK, spaceAfter=0))
    ss.add(ParagraphStyle("Confidential", fontSize=8.5, leading=12, alignment=TA_CENTER,
                          textColor=FAINT))
    ss.add(ParagraphStyle("H1", fontSize=16, leading=20, textColor=INK,
                          fontName="Helvetica-Bold", spaceAfter=2))
    ss.add(ParagraphStyle("Eyebrow", fontSize=8, leading=11, textColor=BLUE,
                          fontName="Helvetica-Bold", spaceAfter=1))
    ss.add(ParagraphStyle("Meta", fontSize=9.5, leading=13, textColor=SUBTLE))
    ss.add(ParagraphStyle("FieldLabel", fontSize=8, leading=11, textColor=FAINT,
                          fontName="Helvetica-Bold", spaceBefore=2, spaceAfter=3))
    ss.add(ParagraphStyle("SubLabel", fontSize=8, leading=11, textColor=SUBTLE,
                          fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=2))
    ss.add(ParagraphStyle("Body", fontSize=9.5, leading=14, textColor=INK, alignment=TA_LEFT))
    ss.add(ParagraphStyle("Mono", fontSize=8.5, leading=12.5, textColor=INK,
                          fontName="Courier"))
    ss.add(ParagraphStyle("Note", fontSize=8, leading=11, textColor=FAINT, spaceBefore=4))
    return ss


def _decorate(canvas, doc, target_url, cover):
    canvas.saveState()
    w, h = A4
    if not cover:
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, h - 14 * mm, w - 18 * mm, h - 14 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(FAINT)
        canvas.drawString(18 * mm, h - 12.5 * mm, "Tonix Agent · Security Assessment Report")
        canvas.drawRightString(w - 18 * mm, h - 12.5 * mm, (target_url or "")[:60])
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, 14 * mm, w - 18 * mm, 14 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(FAINT)
    canvas.drawString(18 * mm, 10 * mm, "CONFIDENTIAL")
    canvas.drawRightString(w - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _clean_host(url: str) -> str:
    host = url.replace("https://", "").replace("http://", "").split("/")[0]
    host = host.replace(":", "_").replace("*", "").strip(".")
    return host or "target"
