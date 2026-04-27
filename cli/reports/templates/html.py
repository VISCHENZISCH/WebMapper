import html

def generate(data, filepath):
    # Pré-génération des lignes de vulnérabilités avec échappement HTML
    vuln_rows = ""
    for v in data.get("vulnerabilities", []):
        vuln_type = html.escape(str(v.get("vuln_type", "Inconnue")))
        vector = html.escape(str(v.get("type", "")))
        url = html.escape(str(v.get("url", "")))
        param = html.escape(str(v.get("param", "")))
        payload = html.escape(str(v.get("payload", "")))
        
        vuln_rows += f"""
        <tr class="vuln-row">
            <td><span class="tag tag-red">{vuln_type}</span></td>
            <td>{vector}</td>
            <td>{url}</td>
            <td>{param}</td>
            <td><code>{payload}</code></td>
        </tr>"""

    if not vuln_rows:
        vuln_rows = '<tr><td colspan="5">Aucune vulnérabilité critique détectée.</td></tr>'

    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WebMapper - Rapport de Scan</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f1f5f9; margin: 0; padding: 20px; }}
            .container {{ max-width: 1000px; margin: auto; background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
            h1 {{ color: #22c55e; border-bottom: 2px solid #22c55e; padding-bottom: 10px; }}
            h2 {{ color: #38bdf8; margin-top: 30px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
            th {{ background: #334155; color: #94a3b8; }}
            .vuln-row {{ background: #450a0a; }}
            .info-row {{ background: #0f172a; }}
            .tag {{ padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
            .tag-red {{ background: #ef4444; color: white; }}
            .tag-yellow {{ background: #f59e0b; color: black; }}
            .footer {{ margin-top: 40px; font-size: 0.9em; color: #64748b; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>WebMapper Sentinel - Rapport d'Analyse</h1>
            <p>Rapport généré automatiquement.</p>
            
            <h2>Vulnerabilités Détectées</h2>
            <table>
                <tr>
                    <th>Vulnérabilité</th>
                    <th>Vecteur</th>
                    <th>URL</th>
                    <th>Paramètre</th>
                    <th>Payload</th>
                </tr>
                {vuln_rows}
            </table>

            <h2>Analyse des Cookies</h2>
            <table>
                <tr>
                    <th>Nom</th>
                    <th>Domaine</th>
                    <th>Secure</th>
                    <th>HttpOnly</th>
                </tr>
                {"".join([f'<tr class="info-row"><td>{c["name"]}</td><td>{c["domain"]}</td><td>{"✔" if c["secure"] else "✘"}</td><td>{"✔" if c["httponly"] else "✘"}</td></tr>' for c in data.get("info", [])]) or '<tr><td colspan="4">Aucun cookie trouvé.</td></tr>'}
            </table>

            <div class="footer">
                &copy; 2025 Félix TOVIGNAN - WebMapper v1.0
            </div>
        </div>
    </body>
    </html>
    """
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)
