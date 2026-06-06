#!/usr/bin/env python3
# coding:utf-8
"""
Module de détection d'injection de commandes OS (Command Injection).

Logique de détection :
  - Time-based : injecter des payloads avec délai (sleep/ping) et mesurer la latence
  - Error-based : rechercher des signatures d'output OS dans la réponse
"""
import time
import urllib.parse
import requests
from bs4 import BeautifulSoup

DELAY = 0.5   # Délai rate-limiting
TIMEOUT = 10  # Timeout réseau de base

# Payloads time-based : (payload_suffixe, délai_attendu_secondes)
TIME_PAYLOADS = [
    ("; sleep 5",              5),
    ("| sleep 5",              5),
    ("& sleep 5 &",            5),
    ("; ping -c 5 127.0.0.1", 5),
    ("& timeout /T 5",         5),  # Windows
    ("| ping -n 5 127.0.0.1",  5),  # Windows
]

# Payloads error-based
ERROR_PAYLOADS = [
    "; whoami",
    "| whoami",
    "& whoami",
    "`whoami`",
    "$(whoami)",
]

# Signatures d'output OS ou d'erreur shell
ERROR_SIGNATURES = [
    "root:x:", "root:0:0", "daemon:", "nobody:", "www-data",  # /etc/passwd
    "administrator", "nt authority",                           # Windows
    "sh:", "bash:", "/bin/sh", "/bin/bash",
    "command not found", "is not recognized as an internal",
]


def _extract_form_fields(form) -> dict:
    """Extrait les champs texte d'un formulaire HTML."""
    params = {}
    for inp in form.find_all(["input", "textarea"]):
        name = inp.get("name")
        if not name:
            continue
        itype = (inp.get("type") or "text").lower()
        if itype in ("submit", "button", "image", "reset", "file", "checkbox", "radio"):
            continue
        params[name] = inp.get("value", "test")
    return params


def _send(session, method, url, params, is_form=False) -> tuple[str, float]:
    """Envoie une requête et retourne (texte_réponse, durée_secondes)."""
    start = time.time()
    try:
        if method == "POST":
            res = session.post(url, data=params, timeout=TIMEOUT + 7)
        else:
            res = session.get(url, params=params, timeout=TIMEOUT + 7)
        return res.text, time.time() - start
    except Exception:
        return "", time.time() - start


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Détecte les vulnérabilités Command Injection via paramètres GET et formulaires.
    S'arrête au premier finding pour limiter le bruit et la durée du scan.
    """
    findings = []
    time.sleep(DELAY)

    # Récupération de la page pour analyser les formulaires
    try:
        response = session.get(url, timeout=TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception:
        return []

    #Paramètres GET dans l'URL 
    parsed = urllib.parse.urlparse(url)
    url_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if url_params:
        # Test time-based
        for payload, delay in TIME_PAYLOADS:
            test = {k: (v[0] + payload) for k, v in url_params.items()}
            text, elapsed = _send(session, "GET", url, test)
            time.sleep(DELAY)
            if elapsed >= delay:
                findings.append({
                    "type": "COMMAND_INJECTION_TIME_BASED",
                    "severity": "critical",
                    "url": url,
                    "detail": "Injection de commande OS détectée via délai anormal sur les paramètres URL.",
                    "evidence": f"Délai observé : {elapsed:.1f}s (attendu ≥ {delay}s) | Payload : {payload}",
                })
                return findings

        # Test error-based
        for payload in ERROR_PAYLOADS:
            test = {k: (v[0] + payload) for k, v in url_params.items()}
            text, _ = _send(session, "GET", url, test)
            time.sleep(DELAY)
            for sig in ERROR_SIGNATURES:
                if sig in text.lower():
                    findings.append({
                        "type": "COMMAND_INJECTION_ERROR_BASED",
                        "severity": "critical",
                        "url": url,
                        "detail": "Injection de commande OS détectée via signature d'erreur dans la réponse.",
                        "evidence": f"Signature : '{sig}' | Payload : {payload}",
                    })
                    return findings

    #Formulaires HTML 
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        target_url = urllib.parse.urljoin(url, action)
        form_params = _extract_form_fields(form)

        if not form_params:
            continue

        # Test time-based (3 premiers payloads pour rester rapide)
        for payload, delay in TIME_PAYLOADS[:3]:
            test = {k: (str(v) + payload) for k, v in form_params.items()}
            text, elapsed = _send(session, method, target_url, test)
            time.sleep(DELAY)
            if elapsed >= delay:
                findings.append({
                    "type": "COMMAND_INJECTION_TIME_BASED",
                    "severity": "critical",
                    "url": target_url,
                    "detail": f"Injection de commande OS détectée via délai anormal sur le formulaire ({method}).",
                    "evidence": f"Délai : {elapsed:.1f}s | Payload : {payload}",
                })
                return findings

        # Test error-based
        for payload in ERROR_PAYLOADS[:3]:
            test = {k: (str(v) + payload) for k, v in form_params.items()}
            text, _ = _send(session, method, target_url, test)
            time.sleep(DELAY)
            for sig in ERROR_SIGNATURES:
                if sig in text.lower():
                    findings.append({
                        "type": "COMMAND_INJECTION_ERROR_BASED",
                        "severity": "critical",
                        "url": target_url,
                        "detail": f"Injection de commande OS détectée via signature d'erreur (formulaire {method}).",
                        "evidence": f"Signature : '{sig}' | Payload : {payload}",
                    })
                    return findings

    return findings
