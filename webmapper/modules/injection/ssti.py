#!/usr/bin/env python3
# coding:utf-8
"""
Logique de détection :
  - Injecter des expressions mathématiques dans les paramètres GET/POST/formulaires
  - Si la réponse contient le résultat évalué (ex: {{7*7}} → "49"), il y a SSTI
  - Les payloads couvrent Jinja2, Twig, Freemarker, Thymeleaf, ERB, Pebble
"""
import time
import urllib.parse
import requests
from bs4 import BeautifulSoup

DELAY = 0.5
TIMEOUT = 10

# Payloads de détection : (payload, résultat_attendu_dans_la_réponse, moteur_cible)
DETECTION_PAYLOADS = [
    ("{{7*7}}",       "49", "Jinja2/Twig"),
    ("${7*7}",        "49", "Freemarker/Groovy"),
    ("#{7*7}",        "49", "Thymeleaf/Spring"),
    ("{{7*'7'}}",     "7777777", "Jinja2"),
    ("<%= 7*7 %>",    "49", "ERB/EL"),
    ("{7*7}",         "49", "Pebble/Smarty"),
    ("[[${7*7}]]",    "49", "Thymeleaf inline"),
    ("${{7*7}}",      "49", "Jinja2 nested"),
]


def _extract_form_fields(form) -> dict:
    """Extrait les champs texte/email/search d'un formulaire."""
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


def _test_params(session, method, url, params, payload, expected) -> tuple[bool, str]:
    """
    Injecte le payload dans chaque paramètre et vérifie si le résultat attendu est reflété.
    Retourne (vulnérable, paramètre_vulnérable).
    """
    for param_name in list(params.keys()):
        test = dict(params)
        test[param_name] = payload
        try:
            time.sleep(DELAY)
            if method == "POST":
                res = session.post(url, data=test, timeout=TIMEOUT)
            else:
                res = session.get(url, params=test, timeout=TIMEOUT)
            if expected in res.text:
                return True, param_name
        except Exception:
            pass
    return False, ""


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Détecte les vulnérabilités SSTI sur les paramètres GET et les formulaires POST.
    """
    findings = []
    time.sleep(DELAY)

    try:
        response = session.get(url, timeout=TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception:
        return []

    #Paramètres GET dans l'URL
    parsed = urllib.parse.urlparse(url)
    url_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    flat_params = {k: v[0] for k, v in url_params.items()}

    if flat_params:
        for payload, expected, engine in DETECTION_PAYLOADS:
            vuln, param = _test_params(session, "GET", url, flat_params, payload, expected)
            if vuln:
                findings.append({
                    "type": "SSTI_DETECTED",
                    "severity": "critical",
                    "url": url,
                    "detail": (
                        f"Server-Side Template Injection détectée sur le paramètre GET '{param}'. "
                        f"Moteur ciblé probable : {engine}."
                    ),
                    "evidence": f"Payload : {payload} → résultat '{expected}' trouvé dans la réponse.",
                })
                return findings  # Un finding SSTI suffit pour alerter

    # Formulaires HTML 
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        target_url = urllib.parse.urljoin(url, action)
        form_params = _extract_form_fields(form)

        if not form_params:
            continue

        for payload, expected, engine in DETECTION_PAYLOADS:
            vuln, param = _test_params(session, method, target_url, form_params, payload, expected)
            if vuln:
                findings.append({
                    "type": "SSTI_DETECTED",
                    "severity": "critical",
                    "url": target_url,
                    "detail": (
                        f"Server-Side Template Injection détectée sur le paramètre '{param}' "
                        f"du formulaire {method}. Moteur ciblé probable : {engine}."
                    ),
                    "evidence": f"Payload : {payload} → résultat '{expected}' trouvé dans la réponse.",
                })
                return findings

    return findings
