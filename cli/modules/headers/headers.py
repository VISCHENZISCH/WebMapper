#!/usr/bin/env python3
# coding:utf-8
"""
Module d'analyse des en-têtes HTTP de sécurité.

Logique de détection :
  - Envoie une requête GET à l'URL cible
  - Vérifie la présence et la configuration de chaque en-tête critique
  - Génère un finding par en-tête absent ou mal configuré
"""
import time
import requests

DELAY = 0.5   # Délai rate-limiting entre les requêtes

# En-têtes critiques attendus, avec sévérité et description
REQUIRED_HEADERS = [
    {
        "name": "Content-Security-Policy",
        "severity": "high",
        "detail": (
            "Content-Security-Policy (CSP) est absent. "
            "Cet en-tête réduit les risques XSS en définissant les sources de contenu autorisées."
        ),
    },
    {
        "name": "X-Frame-Options",
        "severity": "medium",
        "detail": (
            "X-Frame-Options est absent. "
            "Cet en-tête protège contre le clickjacking en interdisant l'intégration dans des iframes."
        ),
    },
    {
        "name": "Strict-Transport-Security",
        "severity": "high",
        "detail": (
            "Strict-Transport-Security (HSTS) est absent. "
            "Cet en-tête force les connexions HTTPS et prévient les attaques de downgrade."
        ),
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "detail": (
            "X-Content-Type-Options est absent. "
            "Cet en-tête bloque le MIME-sniffing du navigateur (valeur attendue : nosniff)."
        ),
    },
    {
        "name": "Referrer-Policy",
        "severity": "low",
        "detail": (
            "Referrer-Policy est absent. "
            "Cet en-tête contrôle les informations de référent envoyées avec chaque requête."
        ),
    },
    {
        "name": "Permissions-Policy",
        "severity": "low",
        "detail": (
            "Permissions-Policy est absent. "
            "Cet en-tête contrôle l'accès aux API sensibles du navigateur (caméra, micro, géoloc…)."
        ),
    },
]

# Validations supplémentaires sur la valeur des en-têtes présents
VALUE_CHECKS = [
    {
        "name": "Strict-Transport-Security",
        "severity": "medium",
        "detail": (
            "HSTS présent mais max-age insuffisant (< 1 an). "
            "Recommandation : max-age=31536000; includeSubDomains; preload"
        ),
        "check": lambda v: (
            "max-age=" in v.lower()
            and _parse_hsts_max_age(v) >= 31536000
        ),
    },
    {
        "name": "Content-Security-Policy",
        "severity": "medium",
        "detail": (
            "CSP présente mais contient 'unsafe-inline' ou 'unsafe-eval', "
            "ce qui neutralise la protection contre les injections XSS."
        ),
        "check": lambda v: "unsafe-inline" not in v.lower() and "unsafe-eval" not in v.lower(),
    },
    {
        "name": "X-Frame-Options",
        "severity": "low",
        "detail": (
            "X-Frame-Options présent avec une valeur non recommandée. "
            "Utiliser DENY ou SAMEORIGIN."
        ),
        "check": lambda v: v.strip().upper() in ("DENY", "SAMEORIGIN"),
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "detail": "X-Content-Type-Options doit valoir 'nosniff'.",
        "check": lambda v: v.strip().lower() == "nosniff",
    },
]


def _parse_hsts_max_age(value: str) -> int:
    """Extrait la valeur de max-age dans un en-tête HSTS."""
    try:
        segment = value.lower().split("max-age=")[1].split(";")[0].strip()
        return int(segment)
    except (IndexError, ValueError):
        return 0


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Point d'entrée du module.
    Analyse les en-têtes HTTP de sécurité de l'URL cible.

    :param url:     URL à analyser
    :param session: Session requests partagée (headers User-Agent déjà configurés)
    :return:        Liste de findings structurés
    """
    findings = []
    time.sleep(DELAY)

    try:
        response = session.get(url, timeout=10)
        headers = response.headers
    except Exception as exc:
        # Erreur réseau : finding informatif, ne fait pas crasher le scanner
        return [{
            "type": "HEADERS_ANALYSIS_ERROR",
            "severity": "info",
            "url": url,
            "detail": f"Impossible d'analyser les en-têtes HTTP : {exc}",
            "evidence": "",
        }]

    # 1. Vérification de la présence des en-têtes critiques
    for hdr in REQUIRED_HEADERS:
        if hdr["name"] not in headers:
            findings.append({
                "type": f"MISSING_HEADER_{hdr['name'].upper().replace('-', '_')}",
                "severity": hdr["severity"],
                "url": url,
                "detail": hdr["detail"],
                "evidence": f"En-tête '{hdr['name']}' absent de la réponse HTTP (status {response.status_code}).",
            })

    # 2. Validation de la valeur des en-têtes présents
    for check in VALUE_CHECKS:
        header_name = check["name"]
        if header_name in headers:
            try:
                if not check["check"](headers[header_name]):
                    findings.append({
                        "type": f"MISCONFIGURED_HEADER_{header_name.upper().replace('-', '_')}",
                        "severity": check["severity"],
                        "url": url,
                        "detail": check["detail"],
                        "evidence": f"{header_name}: {headers[header_name]}",
                    })
            except Exception:
                pass  # Erreur de parsing : on ignore silencieusement

    return findings
