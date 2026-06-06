#!/usr/bin/env python3
# coding:utf-8
"""
Module de détection des mauvaises configurations CORS.

Logique de détection :
  - Envoie une requête avec Origin: https://evil-attacker.com
  - Si la réponse reflète cette origin dans Access-Control-Allow-Origin → CORS misconfiguration
  - Détecte aussi le wildcard (*) avec Access-Control-Allow-Credentials: true (critique)
"""
import time
import requests

DELAY = 0.5
TIMEOUT = 10

EVIL_ORIGIN = "https://evil-attacker.com"


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Détecte les misconfiguration CORS sur l'URL cible.
    """
    findings = []
    time.sleep(DELAY)

    try:
        res = session.get(
            url,
            headers={"Origin": EVIL_ORIGIN},
            timeout=TIMEOUT,
        )
    except Exception:
        return []

    acao = res.headers.get("Access-Control-Allow-Origin", "")
    acac = res.headers.get("Access-Control-Allow-Credentials", "").lower()

    # Cas 1 : reflection de l'origin arbitraire
    if acao == EVIL_ORIGIN:
        severity = "critical" if acac == "true" else "high"
        findings.append({
            "type": "CORS_ORIGIN_REFLECTION",
            "severity": severity,
            "url": url,
            "detail": (
                "L'application reflète l'en-tête Origin arbitraire dans Access-Control-Allow-Origin. "
                + ("Avec Allow-Credentials: true, un attaquant peut voler des données authentifiées cross-origin."
                   if acac == "true"
                   else "Un attaquant peut initier des requêtes cross-origin non autorisées.")
            ),
            "evidence": (
                f"Access-Control-Allow-Origin: {acao} | "
                f"Access-Control-Allow-Credentials: {res.headers.get('Access-Control-Allow-Credentials', 'absent')}"
            ),
        })

    # Cas 2 : wildcard avec credentials
    elif acao == "*" and acac == "true":
        findings.append({
            "type": "CORS_WILDCARD_WITH_CREDENTIALS",
            "severity": "critical",
            "url": url,
            "detail": (
                "CORS mal configuré : Access-Control-Allow-Origin: * combiné avec "
                "Access-Control-Allow-Credentials: true est interdit par le standard et "
                "constitue une faille critique permettant le vol de sessions."
            ),
            "evidence": f"Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
        })

    # Cas 3 : wildcard seul (avertissement selon le contexte)
    elif acao == "*":
        findings.append({
            "type": "CORS_WILDCARD",
            "severity": "medium",
            "url": url,
            "detail": (
                "Access-Control-Allow-Origin: * autorise tout domaine à lire les réponses de cet endpoint. "
                "Problématique si l'endpoint expose des données sensibles."
            ),
            "evidence": f"Access-Control-Allow-Origin: *",
        })

    return findings
