#!/usr/bin/env python3
# coding:utf-8
"""
Logique de détection :
  - Teste une liste de chemins connus (/.git, /.env, /admin, /backup…)
  - Détecte le directory listing actif via la présence de "Index of" dans la réponse
  - Signale les ressources accessibles avec un status 200 non attendu
"""
import time
import urllib.parse
import requests

DELAY = 0.5
TIMEOUT = 10

# Chemins sensibles à tester
SENSITIVE_PATHS = [
    # Contrôle de version
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    # Fichiers de configuration
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.php",
    "/config.yml",
    "/config.json",
    "/settings.py",
    "/application.properties",
    "/wp-config.php",
    # Sauvegardes
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    # Interfaces d'administration
    "/admin",
    "/admin/",
    "/administrator",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/adminer.php",
    # Fichiers de log / debug
    "/error_log",
    "/debug.log",
    "/access.log",
    "/server.log",
    # Autres
    "/robots.txt",
    "/sitemap.xml",
    "/web.config",
    "/.htaccess",
    "/.htpasswd",
    "/server-status",
    "/server-info",
    "/info.php",
    "/phpinfo.php",
    "/test.php",
]

# Signatures de directory listing actif
LISTING_SIGNATURES = [
    "index of /", "directory listing for",
    "<title>index of", "parent directory</a>",
]

# Signatures de fichiers sensibles reconnus dans la réponse
SENSITIVE_CONTENT_SIGNATURES = {
    "/.git/config": ["[core]", "[remote"],
    "/.env":        ["DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY"],
    "/wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD"],
    "/.htpasswd":   [":$apr1$", ":{SHA}"],
}


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Teste les chemins sensibles et détecte le directory listing.
    """
    findings = []
    base = url.rstrip("/")
    parsed = urllib.parse.urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"

    for path in SENSITIVE_PATHS:
        target = root + path
        time.sleep(DELAY)
        try:
            res = session.get(target, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            continue

        if res.status_code not in (200, 403):
            continue  # 404 ou autre → non exposé

        resp_lower = res.text.lower()

        # Détection du directory listing
        for sig in LISTING_SIGNATURES:
            if sig in resp_lower:
                findings.append({
                    "type": "DIRECTORY_LISTING_ENABLED",
                    "severity": "medium",
                    "url": target,
                    "detail": (
                        f"Directory listing activé sur '{path}'. "
                        "Un attaquant peut lister les fichiers du serveur."
                    ),
                    "evidence": f"Signature '{sig}' trouvée | Status: {res.status_code}",
                })
                break

        # Détection de fichiers sensibles exposés (status 200)
        if res.status_code == 200:
            # Vérification du contenu pour les fichiers connus
            sigs = SENSITIVE_CONTENT_SIGNATURES.get(path)
            if sigs:
                for sig in sigs:
                    if sig.lower() in resp_lower:
                        findings.append({
                            "type": "SENSITIVE_FILE_EXPOSED",
                            "severity": "critical",
                            "url": target,
                            "detail": (
                                f"Fichier sensible exposé publiquement : '{path}'. "
                                "Ce fichier peut contenir des identifiants, clés API ou configurations critiques."
                            ),
                            "evidence": f"Signature '{sig}' trouvée dans le contenu | Status 200",
                        })
                        break
            else:
                # Fichiers sans contenu typique mais accessibles (admin, phpMyAdmin…)
                if any(kw in path for kw in ("/admin", "/phpmyadmin", "/server-status", "/info.php", "/phpinfo")):
                    findings.append({
                        "type": "ADMIN_PANEL_ACCESSIBLE",
                        "severity": "high",
                        "url": target,
                        "detail": (
                            f"Interface d'administration ou de diagnostic accessible publiquement : '{path}'. "
                            "L'accès devrait être restreint par IP ou authentification."
                        ),
                        "evidence": f"Status: {res.status_code} | Taille réponse: {len(res.text)} octets",
                    })

    return findings
