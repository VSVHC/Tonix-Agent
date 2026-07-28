"""
reports/html_report.py
──────────────────────
HTML twin of the PDF report — same catalogued per-test-case structure, same
fields, same status derivation (reuses pdf_generator._build_results). Rendered
as a single self-contained, print-friendly HTML document so the report can be
reviewed in a browser and matches the downloadable PDF.

Fields per test case:
  Title · Description · Severity · CVSS Score · Vulnerable Locations ·
  Parameters · Reference Links · Reproduction Steps · Remediation ·
  Sample Code (N/A) · Proof of Concept (request/response) · PoC Images (N/A)
"""

from __future__ import annotations

import html
from pathlib import Path
from datetime import datetime, timezone

from backend.config import settings
from backend.reports.catalog import cvss_band
from backend.reports.pdf_generator import _build_results, _clean_host

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
STATUS_LABEL = {"vulnerable": "Vulnerable", "not_vulnerable": "Not Vulnerable", "not_applicable": "Not Applicable"}


def _e(s) -> str:
    return html.escape(str(s or ""))


def _ref(ref: str) -> str:
    if ": http" in ref:
        label, url = ref.rsplit(": ", 1)
        return f'{_e(label)}: <a href="{_e(url)}" target="_blank" rel="noreferrer">{_e(url)}</a>'
    if ref.startswith("http"):
        return f'<a href="{_e(ref)}" target="_blank" rel="noreferrer">{_e(ref)}</a>'
    return _e(ref)


def generate_html_report(
    scan_id: str,
    target_url: str,
    findings: list[dict],
    counts: dict,
    status_map: dict[str, str] | None = None,
    save_path: str | None = None,
    filename: str | None = None,
) -> str:
    host   = _clean_host(target_url)
    stamp  = datetime.now(timezone.utc)
    fname  = filename or f"{host}_{stamp.strftime('%Y-%m-%d_%H-%M')}.html"
    base   = Path(save_path).expanduser().resolve() if save_path else settings.REPORTS_DIR
    base.mkdir(parents=True, exist_ok=True)
    path   = base / fname

    results = _build_results(findings, status_map)
    vuln = sum(1 for r in results if r["status"] == "vulnerable")
    nvul = sum(1 for r in results if r["status"] == "not_vulnerable")
    na   = sum(1 for r in results if r["status"] == "not_applicable")

    toc_rows = "".join(
        f"""<tr>
          <td class="mono">{r['tc']['id']}</td>
          <td><a href="#{r['tc']['id']}">{_e(r['tc']['title'])}</a></td>
          <td class="mono muted">{_e(r['tc']['module'])}</td>
          <td><span class="status status-{r['status']}">{STATUS_LABEL[r['status']]}</span></td>
          <td>{f'<span class="sev sev-{r["severity"]}">{SEV_LABEL[r["severity"]]}</span>' if r['severity'] else '<span class="muted">—</span>'}</td>
        </tr>"""
        for r in results
    )

    sections = "".join(_section(r) for r in results)

    doc = _SHELL.format(
        target=_e(target_url), date=stamp.strftime("%B %d, %Y"), time=stamp.strftime("%I:%M %p UTC"),
        scan_id=_e(scan_id), total=len(results), vuln=vuln, nvul=nvul, na=na,
        toc_rows=toc_rows, sections=sections, year=stamp.year,
    )
    path.write_text(doc, encoding="utf-8")
    return str(path)


def _section(r: dict) -> str:
    tc, status, sev = r["tc"], r["status"], r["severity"]

    if status == "vulnerable":
        sev_html = f'<span class="sev sev-{sev}">{SEV_LABEL.get(sev, sev)}</span>'
        cvss_html = f'<b>{r["cvss_score"]}</b> <span class="muted">({cvss_band(r["cvss_score"]).title()})</span> · <span class="mono">{_e(r["cvss_vector"])}</span>'
    else:
        sev_html = f'<span class="muted">{STATUS_LABEL[status]}</span>'
        cvss_html = '<span class="muted">N/A</span>'

    urls = []
    for f in r["findings"]:
        for u in (f.get("affected_urls") or []):
            if u not in urls:
                urls.append(u)
    if urls:
        loc = "".join(f'<div class="loc mono">{_e(u)}</div>' for u in urls[:60])
    else:
        loc = ('<span class="muted">None — the target is not vulnerable to this test case.</span>'
               if status == "not_vulnerable" else
               '<span class="muted">Not applicable — test case did not execute.</span>')

    refs = "".join(f"<li>{_ref(x)}</li>" for x in tc["references"])
    steps = "".join(f"<li>{_e(s)}</li>" for s in tc["reproduction"])

    if r.get("poc"):
        f0 = r["poc"]
        poc = ""
        if f0.get("evidence"):
            poc += f'<div class="sublabel">Evidence</div><pre>{_e(f0["evidence"][:2000])}</pre>'
        if f0.get("request_data"):
            poc += f'<div class="sublabel">Request</div><pre>{_e(f0["request_data"][:2000])}</pre>'
        if f0.get("response_data"):
            poc += f'<div class="sublabel">Response</div><pre>{_e(f0["response_data"][:2000])}</pre>'
        if not poc:
            poc = '<span class="muted">No proof-of-concept captured.</span>'
    else:
        poc = ('<span class="muted">No proof-of-concept captured — target not vulnerable to this test case.</span>'
               if status == "not_vulnerable" else
               '<span class="muted">Not applicable — test case did not execute.</span>')

    return f"""
    <section class="tc" id="{tc['id']}">
      <div class="tc-eyebrow">TEST CASE · {tc['id']}</div>
      <h2>{_e(tc['title'])}</h2>
      <div class="tc-meta">
        <span><b>Module:</b> <span class="mono">{_e(tc['module'])}</span></span>
        <span><b>Status:</b> <span class="status status-{status}">{STATUS_LABEL[status]}</span></span>
      </div>

      <div class="field"><div class="label">Description</div><p>{_e(tc['description'])}</p></div>
      <div class="grid2">
        <div class="field"><div class="label">Severity</div><p>{sev_html}</p></div>
        <div class="field"><div class="label">CVSS Score</div><p>{cvss_html}</p></div>
      </div>
      <div class="field"><div class="label">Vulnerable Locations</div><div class="locs">{loc}</div></div>
      <div class="field"><div class="label">Parameters</div><p>{_e(tc['parameters'])}</p></div>
      <div class="field"><div class="label">Reference Links</div><ul class="refs">{refs}</ul></div>
      <div class="field"><div class="label">Reproduction Steps</div><ol class="steps">{steps}</ol></div>
      <div class="field"><div class="label">Remediation</div><div class="callout">{_e(tc['remediation'])}</div></div>
      <div class="field"><div class="label">Sample Code</div><p class="muted">N/A</p></div>
      <div class="field"><div class="label">Proof of Concept</div>{poc}
        <div class="poc-note">PoC Images: N/A (automated assessment — no screenshots captured).</div>
      </div>
    </section>"""


_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Security Assessment Report — {target}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
  :root {{
    --bg:#f6f7f9; --surface:#fff; --surface2:#f1f3f6; --border:#e4e7ec; --border2:#d0d5dd;
    --text:#101828; --text2:#475467; --text3:#98a2b3; --primary:#2563eb; --primary-soft:#eff4ff;
    --sc-fg:#b42318;--sc-bg:#fef3f2;--sc-bd:#fecdca; --sh-fg:#b93815;--sh-bg:#fff4ed;--sh-bd:#f9dbaf;
    --sm-fg:#854a0e;--sm-bg:#fefbe8;--sm-bd:#feee95; --sl-fg:#067647;--sl-bg:#ecfdf3;--sl-bd:#abefc6;
    --si-fg:#175cd3;--si-bg:#eff8ff;--si-bd:#b2ddff;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg:#0b0f16;--surface:#131924;--surface2:#1b2230;--border:#253040;--border2:#34435b;
      --text:#e6edf5;--text2:#9aa8bd;--text3:#64748b;--primary:#3b82f6;--primary-soft:#16233b;
      --sc-fg:#fda29b;--sc-bg:rgba(240,68,56,.14);--sc-bd:rgba(240,68,56,.34);
      --sh-fg:#fdb373;--sh-bg:rgba(247,144,9,.14);--sh-bd:rgba(247,144,9,.34);
      --sm-fg:#fde272;--sm-bg:rgba(234,179,8,.14);--sm-bd:rgba(234,179,8,.32);
      --sl-fg:#75e0a7;--sl-bg:rgba(18,183,106,.14);--sl-bd:rgba(18,183,106,.34);
      --si-fg:#84caff;--si-bg:rgba(46,144,250,.14);--si-bd:rgba(46,144,250,.34);
    }}
  }}
  *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);
    font-family:'Inter',system-ui,-apple-system,'Segoe UI',sans-serif;font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}}
  .mono{{font-family:'JetBrains Mono',ui-monospace,monospace}} .muted{{color:var(--text3)}}
  a{{color:var(--primary);text-decoration:none;word-break:break-all}} a:hover{{text-decoration:underline}}
  .wrap{{max-width:900px;margin:0 auto;padding:40px 24px 80px}}
  .cover{{text-align:center;padding:48px 0 32px;border-bottom:1px solid var(--border);margin-bottom:32px}}
  .cover .eyebrow{{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--text2);margin-bottom:10px}}
  .cover .eyebrow .pip{{width:6px;height:6px;border-radius:50%;background:var(--primary)}}
  .cover h1{{font-size:28px;font-weight:700;letter-spacing:-.01em;margin:0 0 6px}}
  .cover .target{{font-family:'JetBrains Mono',monospace;color:var(--primary);font-size:15px}}
  .cover-meta{{display:flex;gap:28px;justify-content:center;flex-wrap:wrap;margin-top:16px;font-size:12px;color:var(--text2)}}
  .cover-meta b{{color:var(--text3);text-transform:uppercase;font-size:10px;letter-spacing:.05em;display:block}}
  .cover-meta .v{{color:var(--text);font-weight:500;margin-top:2px}}
  .confidential{{margin-top:20px;font-size:11px;color:var(--text3)}}
  h3.sec{{font-size:15px;font-weight:600;margin:0 0 14px}}
  table.toc{{width:100%;border-collapse:collapse;font-size:13px;background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}}
  table.toc th{{background:var(--primary);color:#fff;text-align:left;padding:9px 12px;font-size:11px;text-transform:uppercase;letter-spacing:.04em}}
  table.toc td{{padding:8px 12px;border-top:1px solid var(--border)}}
  table.toc tr:nth-child(even) td{{background:var(--surface2)}}
  .totals{{display:flex;gap:24px;flex-wrap:wrap;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 16px;margin:14px 0 40px;font-size:13px}}
  .totals b{{font-variant-numeric:tabular-nums}}
  .status{{font-size:11px;font-weight:600}} .status-vulnerable{{color:var(--sc-fg)}} .status-not_vulnerable{{color:var(--sl-fg)}} .status-not_applicable{{color:var(--text3)}}
  .sev{{display:inline-block;font-size:11px;font-weight:600;padding:2px 9px;border-radius:999px;border:1px solid transparent}}
  .sev-critical{{color:var(--sc-fg);background:var(--sc-bg);border-color:var(--sc-bd)}}
  .sev-high{{color:var(--sh-fg);background:var(--sh-bg);border-color:var(--sh-bd)}}
  .sev-medium{{color:var(--sm-fg);background:var(--sm-bg);border-color:var(--sm-bd)}}
  .sev-low{{color:var(--sl-fg);background:var(--sl-bg);border-color:var(--sl-bd)}}
  .sev-info{{color:var(--si-fg);background:var(--si-bg);border-color:var(--si-bd)}}
  section.tc{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px;box-shadow:0 1px 2px rgba(16,24,40,.04)}}
  .tc-eyebrow{{font-size:11px;font-weight:600;color:var(--primary);text-transform:uppercase;letter-spacing:.05em}}
  section.tc h2{{font-size:18px;font-weight:700;margin:2px 0 8px}}
  .tc-meta{{display:flex;gap:24px;flex-wrap:wrap;font-size:13px;color:var(--text2);padding-bottom:14px;border-bottom:1px solid var(--border);margin-bottom:16px}}
  .field{{margin-bottom:16px}} .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
  .label{{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--text3);margin-bottom:5px}}
  .field p{{margin:0}} .sublabel{{font-size:11px;font-weight:600;color:var(--text2);margin:10px 0 4px}}
  .loc{{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:5px 9px;font-size:12px;margin-bottom:4px;word-break:break-all}}
  ul.refs{{margin:0;padding-left:18px}} ul.refs li{{margin-bottom:6px;font-size:13px}}
  ol.steps{{margin:0;padding-left:20px}} ol.steps li{{margin-bottom:5px}}
  .callout{{background:var(--sl-bg);border:1px solid var(--sl-bd);border-radius:8px;padding:12px 14px;font-size:13px}}
  pre{{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:11px 13px;font-family:'JetBrains Mono',monospace;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:var(--text2);max-height:340px;overflow-y:auto;margin:0 0 10px}}
  .poc-note{{margin-top:8px;font-size:12px;color:var(--text3)}}
  .footer{{margin-top:32px;padding-top:16px;border-top:1px solid var(--border);display:flex;justify-content:space-between;font-size:11px;color:var(--text3);flex-wrap:wrap;gap:6px}}
  @media (max-width:640px){{.grid2{{grid-template-columns:1fr}}}}
  @media print{{body{{background:#fff}} section.tc{{break-inside:avoid;box-shadow:none}}}}
</style>
</head>
<body>
<div class="wrap">
  <div class="cover">
    <div class="eyebrow"><span class="pip"></span> Unauthenticated blackbox assessment</div>
    <h1>Web Application Security Assessment Report</h1>
    <div class="target">{target}</div>
    <div class="cover-meta">
      <div><b>Date</b><div class="v">{date}</div></div>
      <div><b>Time</b><div class="v">{time}</div></div>
      <div><b>Scan ID</b><div class="v mono">{scan_id}</div></div>
    </div>
    <div class="confidential">CONFIDENTIAL — Intended solely for authorized recipients. Unauthorized disclosure is prohibited.</div>
  </div>

  <h3 class="sec">Table of Contents</h3>
  <table class="toc">
    <thead><tr><th>ID</th><th>Test Case</th><th>Module</th><th>Status</th><th>Severity</th></tr></thead>
    <tbody>{toc_rows}</tbody>
  </table>
  <div class="totals">
    <span>Vulnerable <b class="status-vulnerable">{vuln}</b></span>
    <span>Not Vulnerable <b class="status-not_vulnerable">{nvul}</b></span>
    <span>Not Applicable <b>{na}</b></span>
    <span>Total <b>{total}</b></span>
  </div>

  {sections}

  <div class="footer">
    <span>Generated by Tonix Agent · Scan ID: {scan_id}</span>
    <span>All data stored locally</span>
  </div>
</div>
</body>
</html>"""
