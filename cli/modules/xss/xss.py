#!/usr/bin/env python3
# coding:utf-8
"""
Module de détection XSS - refactorisé selon la nouvelle convention.
Expose : scan(url, session) -> list[dict]

Logique :
  - Injecter des payloads XSS dans les paramètres GET, les formulaires HTML et les en-têtes
  - Détecter si le payload est reflété sans encodage dans la réponse
  - Tester chaque champ individuellement (y compris hidden)
"""
import html as html_module
import time
import logging
import urllib.parse
import requests
from bs4 import BeautifulSoup
from utils import extract_form_fields

logger = logging.getLogger("webmapper.xss")

DELAY = 0.5
TIMEOUT = 10

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
    "<body onload=alert(1)>",
]


def _is_reflected(response_text: str, payload: str) -> bool:
    """Vérifie si le payload est reflété (brut ou partiellement encodé)."""
    if payload in response_text:
        return True
    if payload in html_module.unescape(response_text):
        return True
    return False


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Détecte les vulnérabilités XSS reflected via paramètres GET, formulaires et en-têtes.
    Teste chaque champ individuellement avec déduplication.
    """
    findings = []
    seen = set()

    def add_finding(f):
        key = (f["type"], f.get("url"), f.get("evidence", "")[:40])
        if key not in seen:
            seen.add(key)
            findings.append(f)

    time.sleep(DELAY)

    try:
        response = session.get(url, timeout=TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as exc:
        logger.debug("Impossible de récupérer %s : %s", url, exc)
        return []

    # 1. Paramètres GET dans l'URL
    parsed = urllib.parse.urlparse(url)
    url_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    for param_name in url_params:
        for payload in XSS_PAYLOADS:
            test = dict(url_params)
            test[param_name] = [payload]
            new_query = urllib.parse.urlencode(test, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            try:
                time.sleep(DELAY)
                res = session.get(test_url, timeout=TIMEOUT)
                if _is_reflected(res.text, payload):
                    add_finding({
                        "type": "XSS_REFLECTED",
                        "severity": "high",
                        "url": url,
                        "detail": f"XSS Reflected détecté sur le paramètre GET '{param_name}'.",
                        "evidence": f"Payload reflété : {payload[:80]}",
                    })
                    break  # Un seul payload suffit par paramètre, passer au suivant
            except Exception as exc:
                logger.debug("Erreur test XSS GET param '%s' sur %s : %s", param_name, url, exc)

    # 2. Formulaires HTML - tester chaque champ individuellement
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        target_url = urllib.parse.urljoin(url, action)

        template, injectable_names = extract_form_fields(form, include_hidden=True)

        if not injectable_names:
            continue

        for field_name in injectable_names:
            for payload in XSS_PAYLOADS:
                params = template.copy()
                params[field_name] = payload
                try:
                    time.sleep(DELAY)
                    if method == "POST":
                        res = session.post(target_url, data=params, timeout=TIMEOUT)
                    else:
                        res = session.get(target_url, params=params, timeout=TIMEOUT)

                    if _is_reflected(res.text, payload):
                        add_finding({
                            "type": "XSS_REFLECTED",
                            "severity": "high",
                            "url": target_url,
                            "detail": f"XSS Reflected détecté dans le formulaire {method} (champ : '{field_name}').",
                            "evidence": f"Payload reflété : {payload[:80]}",
                        })
                        break  # Un seul payload suffit par champ
                except Exception as exc:
                    logger.debug("Erreur test XSS formulaire champ '%s' sur %s : %s", field_name, target_url, exc)

    # 3. Injection d'en-têtes HTTP
    target_headers = ["X-Forwarded-For", "User-Agent", "Referer"]
    for header in target_headers:
        for payload in XSS_PAYLOADS[:3]:  # Limiter les payloads sur les headers
            try:
                time.sleep(DELAY)
                res = session.get(url, headers={header: payload}, timeout=TIMEOUT)
                if _is_reflected(res.text, payload):
                    add_finding({
                        "type": "XSS_REFLECTED_HEADER",
                        "severity": "high",
                        "url": url,
                        "detail": f"XSS Reflected détecté via l'en-tête HTTP '{header}'.",
                        "evidence": f"Payload reflété : {payload[:80]}",
                    })
                    break  # Un seul payload suffit par header
            except Exception as exc:
                logger.debug("Erreur test XSS header '%s' sur %s : %s", header, url, exc)

    return findings
