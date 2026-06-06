#!/usr/bin/env python3
# coding:utf-8
"""
Design sombre, affichage par sévérité avec badges colorés.
"""
import html as html_lib
from datetime import datetime


# Couleur CSS par sévérité
SEVERITY_COLORS = {
    "critical": ("#ff4757", "#2d0a0a"),
    "high":     ("#ff6b35", "#2d150a"),
    "medium":   ("#ffa502", "#2d1f0a"),
    "low":      ("#2ed573", "#0a2d16"),
    "info":     ("#70a1ff", "#0a1a2d"),
}

SEVERITY_LABELS = {
    "critical": "CRITIQUE",
    "high":     "ÉLEVÉ",
    "medium":   "MOYEN",
    "low":      "FAIBLE",
    "info":     "INFO",
}


def _badge(severity: str) -> str:
    color, _ = SEVERITY_COLORS.get(severity.lower(), ("#aaa", "#1a1a1a"))
    label = SEVERITY_LABELS.get(severity.lower(), severity.upper())
    return (f'<span style="background:{color};color:#fff;padding:3px 10px;'
            f'border-radius:12px;font-size:.75em;font-weight:700;'
            f'letter-spacing:.5px">{label}</span>')


def generate(data: dict, filepath: str):
    findings = data.get("findings", [])
    summary  = data.get("summary", {})
    total    = data.get("total", 0)
    ts       = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

    # Résumé des compteurs
    summary_html = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        count = summary.get(sev, 0)
        color, bg = SEVERITY_COLORS.get(sev, ("#aaa", "#1a1a1a"))
        label = SEVERITY_LABELS.get(sev, sev.upper())
        summary_html += (
            f'<div style="background:{bg};border:1px solid {color};border-radius:8px;'
            f'padding:14px 20px;text-align:center;min-width:100px">'
            f'<div style="color:{color};font-size:2em;font-weight:700">{count}</div>'
            f'<div style="color:#ccc;font-size:.8em;margin-top:4px">{label}</div>'
            f'</div>'
        )

    # Lignes du tableau de findings
    rows_html = ""
    if not findings:
        rows_html = ('<tr><td colspan="5" style="text-align:center;color:#64748b;padding:30px">'
                     'Aucune vulnérabilité détectée.</td></tr>')
    else:
        for f in findings:
            sev      = f.get("severity", "info").lower()
            _, bg    = SEVERITY_COLORS.get(sev, ("#aaa", "#1a1a1a"))
            ftype    = html_lib.escape(str(f.get("type", "")))
            url      = html_lib.escape(str(f.get("url", "")))
            detail   = html_lib.escape(str(f.get("detail", "")))
            evidence = html_lib.escape(str(f.get("evidence", "")))

            rows_html += f"""
            <tr style="background:{bg};border-bottom:1px solid #1e293b">
                <td style="padding:12px 14px">{_badge(sev)}</td>
                <td style="padding:12px 14px;font-family:monospace;font-size:.82em;color:#38bdf8">{ftype}</td>
                <td style="padding:12px 14px;font-size:.82em;word-break:break-all">
                    <a href="{url}" style="color:#7dd3fc;text-decoration:none">{url}</a>
                </td>
                <td style="padding:12px 14px;font-size:.85em">{detail}</td>
                <td style="padding:12px 14px;font-family:monospace;font-size:.78em;color:#94a3b8">{evidence}</td>
            </tr>"""

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>WebMapper — Rapport de Scan</title>
    <style>
        *{{box-sizing:border-box;margin:0;padding:0}}
        body{{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;
              background:#0a0f1e;color:#e2e8f0;min-height:100vh;padding:24px}}
        .container{{max-width:1280px;margin:auto}}
        .header{{background:linear-gradient(135deg,#0f172a,#1e293b);
                 border:1px solid #334155;border-radius:12px;padding:28px 32px;margin-bottom:24px}}
        .header h1{{color:#22c55e;font-size:1.8em;margin-bottom:6px}}
        .header .meta{{color:#64748b;font-size:.9em}}
        .summary{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:24px}}
        .section{{background:#0f172a;border:1px solid #1e293b;border-radius:12px;
                  overflow:hidden;margin-bottom:24px}}
        .section-title{{background:#1e293b;padding:14px 20px;color:#38bdf8;
                        font-size:1em;font-weight:600;border-bottom:1px solid #334155}}
        table{{width:100%;border-collapse:collapse}}
        th{{background:#1e293b;color:#94a3b8;font-size:.8em;text-transform:uppercase;
            letter-spacing:.6px;padding:12px 14px;text-align:left;font-weight:600}}
        .footer{{text-align:center;color:#334155;font-size:.82em;margin-top:32px;padding:16px}}
        .total-badge{{display:inline-block;background:#1e293b;border:1px solid #334155;
                      border-radius:8px;padding:6px 16px;color:#e2e8f0;font-size:.9em;margin-top:8px}}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>&#x1F6E1; WebMapper — Rapport d'Analyse de Sécurité</h1>
        <div class="meta">Généré le {ts}</div>
        <div class="total-badge">{total} finding(s) au total</div>
    </div>

    <div class="summary">
        {summary_html}
    </div>

    <div class="section">
        <div class="section-title">&#x26A0; Findings de sécurité</div>
        <table>
            <thead>
                <tr>
                    <th>Sévérité</th>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Détail</th>
                    <th>Preuve</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>

    <div class="footer">
        &copy; 2025 Félix TOVIGNAN — WebMapper v2.0 &nbsp;|&nbsp;
        <a href="https://github.com/VISCHENZISCH/WebMapper" style="color:#334155">GitHub</a>
    </div>
</div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html_content)
