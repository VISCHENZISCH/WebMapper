#!/usr/bin/env python3
# coding:utf-8
"""
Rapport HTML WebMapper - Design moderne et premium
"""
import html as html_lib
from datetime import datetime

# Palette de couleurs sémantiques par sévérité (Accent, Fond, Texte)
SEVERITY_THEMES = {
    "critical": {
        "color": "#dc2626",      # Rouge vif
        "bg": "#fef2f2",         # Fond très clair rouge
        "text": "#991b1b",       # Texte sombre rouge
        "label": "CRITIQUE"
    },
    "high": {
        "color": "#f97316",      # Orange vif
        "bg": "#fff7ed",         # Fond très clair orange
        "text": "#9a3412",       # Texte sombre orange
        "label": "ÉLEVÉ"
    },
    "medium": {
        "color": "#d97706",      # Doré
        "bg": "#fffbeb",         # Fond très clair doré
        "text": "#854d0e",       # Texte sombre doré
        "label": "MOYEN"
    },
    "low": {
        "color": "#16a34a",      # Vert émeraude
        "bg": "#f0fdf4",         # Fond très clair vert
        "text": "#166534",       # Texte sombre vert
        "label": "FAIBLE"
    },
    "info": {
        "color": "#2563eb",      # Bleu électrique
        "bg": "#eff6ff",         # Fond très clair bleu
        "text": "#1e40af",       # Texte sombre bleu
        "label": "INFO"
    }
}


def _badge(severity: str) -> str:
    theme = SEVERITY_THEMES.get(severity.lower(), {
        "color": "#64748b",
        "bg": "#f8fafc",
        "text": "#334155",
        "label": severity.upper()
    })
    return (f'<span class="badge" style="background:{theme["color"]};color:#ffffff">'
            f'{theme["label"]}</span>')


def generate(data: dict, filepath: str):
    findings = data.get("findings", [])
    total    = data.get("total", 0)
    ts       = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

    # Lignes du tableau de findings
    rows_html = ""
    if not findings:
        rows_html = ('<tr><td colspan="5" style="text-align:center;color:#64748b;padding:30px;font-size:1.1em">'
                     'Aucune vulnérabilité détectée.</td></tr>')
    else:
        for f in findings:
            sev      = f.get("severity", "info").lower()
            theme    = SEVERITY_THEMES.get(sev, {
                "color": "#64748b", "bg": "#ffffff", "text": "#334155"
            })
            ftype    = html_lib.escape(str(f.get("type", "")))
            url      = html_lib.escape(str(f.get("url", "")))
            detail   = html_lib.escape(str(f.get("detail", "")))
            evidence = html_lib.escape(str(f.get("evidence", "")))

            # Application du style de ligne dynamique avec bordure de gauche colorée
            rows_html += f"""
            <tr style="background:{theme['bg']}; border-left: 5px solid {theme['color']};">
                <td style="padding:10px 12px; white-space:nowrap; max-width:0; overflow:hidden;">{_badge(sev)}</td>
                <td style="padding:10px 12px; font-family:var(--font-mono); font-size:0.88em; color:var(--ink); font-weight:700; word-break:break-all; overflow-wrap:anywhere; max-width:0; overflow:hidden;">{ftype}</td>
                <td style="padding:10px 12px; font-size:0.88em; word-break:break-all; overflow-wrap:anywhere; max-width:0; overflow:hidden;">
                    <a href="{url}" target="_blank">{url}</a>
                </td>
                <td style="padding:10px 12px; font-size:0.90em; color:var(--ink); word-break:break-word; overflow-wrap:anywhere; max-width:0; overflow:hidden;">{detail}</td>
                <td style="padding:10px 12px; font-family:var(--font-mono); font-size:0.82em; color:var(--muted); word-break:break-word; overflow-wrap:anywhere; max-width:0; overflow:hidden;">{evidence}</td>
            </tr>"""

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>WebMapper - Rapport de Scan</title>
    <style>
        :root {{
            --page: #f1f5f9;
            --ink: #0f172a;
            --muted: #475569;
            --surface: #ffffff;
            --line: #e2e8f0;
            --navy: #0f172a;
            --accent: #2563eb;
            --link: #0284c7;
            --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
            --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: var(--font-sans);
            background: var(--page);
            color: var(--ink);
            min-height: 100vh;
            padding: 0;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{
            max-width: 1600px;
            margin: 0 auto;
            padding: 8px 12px 16px;
        }}
        .header {{
            background: var(--navy);
            color: #ffffff;
            border-radius: 8px;
            padding: 20px 24px;
            margin-bottom: 16px;
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 16px;
            align-items: center;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
        }}
        .header h1 {{
            color: #ffffff;
            font-size: 2.1em;
            font-weight: 800;
            letter-spacing: -0.5px;
        }}
        .header .meta {{
            color: #94a3b8;
            font-size: 1.05em;
            margin-top: 4px;
        }}
        .total-badge {{
            background: #ffffff;
            color: #0f172a;
            border-radius: 6px;
            padding: 8px 16px;
            font-size: 1.05em;
            font-weight: 800;
            white-space: nowrap;
            box-shadow: 0 1px 3px rgb(0 0 0 / 0.1);
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--line);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 16px;
            box-shadow: 0 1px 3px rgb(0 0 0 / 0.05);
        }}
        .section-title {{
            background: #ffffff;
            border-bottom: 3px solid var(--navy);
            color: var(--ink);
            padding: 14px 18px;
            font-size: 1.15em;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
            table-layout: fixed;
        }}
        th {{
            background: #f8fafc;
            color: #475569;
            border-bottom: 2px solid var(--line);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            text-align: left;
            padding: 12px 16px;
            font-weight: 800;
        }}
        td {{
            color: var(--ink);
            vertical-align: middle;
            border-bottom: 1px solid #e2e8f0;
        }}
        tr {{
            transition: background 0.15s;
        }}
        tr:hover {{
            background: #f8fafc !important;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            font-size: 0.85em;
            font-weight: 800;
            letter-spacing: 0.5px;
            border-radius: 4px;
            text-transform: uppercase;
            text-align: center;
        }}
        a {{
            color: var(--link);
            text-decoration: none;
            font-weight: 700;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .footer {{
            text-align: left;
            color: var(--muted);
            font-size: 0.95em;
            margin-top: 16px;
            padding: 12px 0;
            border-top: 1px solid var(--line);
        }}
        @media (max-width: 768px) {{
            .container {{
                padding: 12px;
            }}
            .header {{
                grid-template-columns: 1fr;
                padding: 16px;
            }}
            .header h1 {{
                font-size: 1.7em;
            }}
            .section {{
                overflow-x: auto;
            }}
            table {{
                min-width: 900px;
            }}
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>WebMapper - Rapport d'Analyse de Sécurité</h1>
            <div class="meta">Généré le {ts}</div>
        </div>
        <div class="total-badge">{total} finding(s) au total</div>
    </div>

    <div class="section">
        <div class="section-title">Findings de sécurité</div>
        <table>
            <colgroup>
                <col style="width: 9%;">
                <col style="width: 30%;">
                <col style="width: 26%;">
                <col style="width: 21%;">
                <col style="width: 14%;">
            </colgroup>
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
        &copy; 2026 Félix TOVIGNAN - WebMapper v2.0 &nbsp;|&nbsp;
        <a href="https://github.com/VISCHENZISCH/WebMapper" style="color:var(--muted)">GitHub</a>
    </div>
</div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html_content)
