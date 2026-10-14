"""Report generator (Stage 4) — self-contained HTML + real PDF via Qt.

Findings are rendered exactly as recorded. Nothing is invented here.
"""
import html
import os
import time

TEMPLATE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{title}</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0b0f0b;color:#d8ffd0;margin:24px}}
h1{{color:#39ff14;letter-spacing:1px}} h2{{border-bottom:1px solid #2a3a2a;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%;margin:10px 0 24px}}
th,td{{border:1px solid #2a3a2a;padding:8px;text-align:left;font-size:13px;vertical-align:top}}
th{{background:#111711}} .crit{{color:#ff2e4d;font-weight:700}} .high{{color:#ff8c1a;font-weight:700}}
.med{{color:#ffd60a}} .low{{color:#35c4ff}} .info{{color:#9aa5a0}}
.meta{{color:#7d8a7d;font-size:12px}} .confirmed{{color:#ff2e4d;font-weight:700}}
.potential{{color:#ffd60a;font-weight:700}} .scope{{background:#111711;padding:10px;border-radius:8px}}
</style></head><body>
<h1>DERYCODE CYBERSECURITY — VULNERABILITY ASSESSMENT REPORT</h1>
<div class="meta">Report ID: <b>{report_id}</b><br>Generated: {generated}<br>
Assessment target: <b>{target}</b><br>Modules executed: {modules}<br>
Authorization scope: {scope}</div>
<div class="scope"><b>Authorized scope statement:</b> {scope_text}</div>
<h2>Summary</h2>
<p class="meta">Confirmed findings: {confirmed} · Potential findings: {potential}</p>
{summary_table}
<h2>Findings</h2>
{findings_html}
<p class="meta">Confidence legend: <span class="confirmed">confirmed</span> = verified
evidence; <span class="potential">potential</span> = needs verification. Potential findings
must not be treated as confirmed vulnerabilities.</p>
</body></html>"""


def severity_class(sev):
    return {"critical": "crit", "high": "high", "medium": "med",
            "low": "low", "informational": "info"}.get(sev, "info")


def generate_html(db, scan_id, out_dir):
    scan = db.query_one(
        "SELECT s.*, a.name AS asset_name, a.target FROM scans s "
        "JOIN assets a ON a.id = s.asset_id WHERE s.id = ?", (scan_id,))
    findings = db.query("SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,))
    auth = db.query_one(
        "SELECT scope, authorized_by, valid_until FROM authorizations "
        "WHERE asset_id = ? ORDER BY id DESC LIMIT 1", (scan["asset_id"],))
    os.makedirs(out_dir, exist_ok=True)
    report_id = f"DCS-{scan_id:04d}-{int(time.time())}"
    out = os.path.join(out_dir, f"{report_id}.html")

    rows = []
    for f in findings:
        rows.append(
            f"<tr><td class='{severity_class(f['severity'])}'>{f['severity'].upper()}</td>"
            f"<td>{html.escape(f['title'])}<br><span class='meta'>Category: {f['category'] or '—'}"
            f" · Confidence: <span class='{f['confidence']}'>{f['confidence']}</span></span></td>"
            f"<td><pre style='white-space:pre-wrap'>{html.escape(f['evidence'] or '—')}</pre></td>"
            f"<td>{html.escape(f['impact'] or '—')}</td>"
            f"<td>{html.escape(f['remediation'] or '—')}</td></tr>")

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = "".join(
        f"<tr><td class='{severity_class(k)}'>{k.upper()}</td><td>{v}</td></tr>"
        for k, v in sorted(counts.items()))

    page = TEMPLATE.format(
        title=f"Derycode Cybersecurity — Assessment {report_id}",
        report_id=report_id,
        generated=time.strftime("%Y-%m-%d %H:%M"),
        target=f"{scan['asset_name']} ({scan['target']})",
        modules=scan["module"],
        scope=auth["scope"] if auth else "not recorded",
        scope_text=html.escape((auth["scope"] if auth else "") +
                               (f" — authorized by {auth['authorized_by']}"
                                f" until {auth['valid_until']}" if auth else "")),
        confirmed=sum(1 for f in findings if f["confidence"] == "confirmed"),
        potential=sum(1 for f in findings if f["confidence"] == "potential"),
        summary_table=f"<table><tr><th>Severity</th><th>Count</th></tr>{summary}</table>",
        findings_html=("<table><tr><th>Severity</th><th>Finding</th><th>Evidence</th>"
                       "<th>Impact</th><th>Remediation</th></tr>" + "".join(rows) +
                       "</table>") if rows else "<p>No findings recorded.</p>")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(page)

    db.execute("INSERT INTO reports (scan_id, title, fmt, path) VALUES (?,?,?,?)",
               (scan_id, f"Assessment {report_id}", "html", out))
    db.audit("report.generate", target=report_id, details={"scan_id": scan_id})
    return out


def generate_pdf(db, scan_id, out_dir):
    """Real PDF via Qt (QPdfWriter) — requires a QApplication (offscreen works)."""
    from PySide6.QtGui import QPdfWriter, QTextDocument
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    html_path = generate_html(db, scan_id, out_dir)
    base = os.path.splitext(html_path)[0]
    out = base + ".pdf"
    document = QTextDocument()
    with open(html_path, encoding="utf-8") as fh:
        document.setHtml(fh.read())
    writer = QPdfWriter(out)
    writer.setResolution(96)
    writer.setPageMargins(QPdfWriter.Margins(30, 30, 30, 30, writer.resolution()))
    document.print_(writer)
    db.execute("INSERT INTO reports (scan_id, title, fmt, path) VALUES (?,?,?,?)",
               (scan_id, f"Assessment {os.path.basename(out)}", "pdf", out))
    return out
