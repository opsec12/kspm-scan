from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from kspm.models import Finding, Severity
from kspm.scanner import compute_posture_score, summarize_by_severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#7f1d1d",
    Severity.HIGH: "#b91c1c",
    Severity.MEDIUM: "#b45309",
    Severity.LOW: "#0369a1",
    Severity.INFO: "#6b7280",
}

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>KSPM Scan Report</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
          background: #f8fafc; color: #0f172a; }}
  header {{ padding: 24px 32px; background: #0f172a; color: #f8fafc; }}
  header h1 {{ margin: 0 0 4px; font-size: 20px; }}
  header p {{ margin: 0; color: #94a3b8; font-size: 13px; }}
  .summary {{ display: flex; gap: 16px; padding: 24px 32px; flex-wrap: wrap; }}
  .card {{ background: #fff; border-radius: 10px; padding: 16px 20px;
           box-shadow: 0 1px 3px rgba(0,0,0,0.08); min-width: 140px; }}
  .card .value {{ font-size: 28px; font-weight: 700; }}
  .card .label {{ font-size: 12px; color: #64748b; text-transform: uppercase;
                  letter-spacing: 0.05em; }}
  main {{ padding: 0 32px 40px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border-radius: 10px; overflow: hidden;
           box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  th, td {{ text-align: left; padding: 10px 14px; border-bottom: 1px solid #e2e8f0;
            font-size: 13px; vertical-align: top; }}
  th {{ background: #f1f5f9; font-size: 11px; text-transform: uppercase;
        color: #475569; letter-spacing: 0.05em; }}
  .sev {{ display: inline-block; padding: 2px 8px; border-radius: 999px;
          color: #fff; font-weight: 600; font-size: 11px; }}
  .empty {{ padding: 40px; text-align: center; color: #16a34a; font-weight: 600; }}
  code {{ background: #f1f5f9; padding: 1px 4px; border-radius: 4px; }}
</style>
</head>
<body>
<header>
  <h1>KSPM Scan Report</h1>
  <p>Generated {generated_at} &middot; {scanned_count} workload(s) scanned</p>
</header>
<div class="summary">
  <div class="card"><div class="value">{score}/100</div><div class="label">Posture score</div></div>
  {severity_cards}
</div>
<main>
{body}
</main>
</body>
</html>
"""


def render_html(findings: list[Finding], scanned_count: int) -> str:
    score = compute_posture_score(findings)
    counts = summarize_by_severity(findings)

    severity_cards = "".join(
        f'<div class="card"><div class="value">{count}</div>'
        f'<div class="label">{escape(sev)}</div></div>'
        for sev, count in counts.items()
        if count
    )

    if not findings:
        body = '<div class="empty">No security posture issues found.</div>'
    else:
        rows = []
        for f in findings:
            color = _SEVERITY_COLOR[f.severity]
            rows.append(
                "<tr>"
                f'<td><span class="sev" style="background:{color}">{escape(f.severity.value)}</span></td>'
                f"<td><code>{escape(f.rule_id)}</code></td>"
                f"<td>{escape(f.workload.locator)}</td>"
                f"<td>{escape(f.container or '-')}</td>"
                f"<td>{escape(f.message)}<br><small>{escape(f.remediation)}</small></td>"
                "</tr>"
            )
        body = (
            "<table><thead><tr><th>Severity</th><th>Rule</th><th>Workload</th>"
            "<th>Container</th><th>Finding &amp; remediation</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    return _TEMPLATE.format(
        generated_at=escape(datetime.now(timezone.utc).isoformat()),
        scanned_count=scanned_count,
        score=score,
        severity_cards=severity_cards,
        body=body,
    )
