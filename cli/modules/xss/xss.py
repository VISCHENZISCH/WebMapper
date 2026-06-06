#!/usr/bin/env python3
# coding:utf-8
"""
Module de détection XSS — refactorisé selon la nouvelle convention.
Expose : scan(url, session) -> list[dict]

Logique :
  - Injecter des payloads XSS dans les paramètres GET et les formulaires HTML
  - Détecter si le payload est reflété sans encodage dans la réponse
"""
import html as html_module
import time
import urllib.parse
import requests
from bs4 import BeautifulSoup

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


def _extract_form_params(form, payload: str) -> dict:
    """Remplit les champs texte d'un formulaire avec le payload XSS."""
    params = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        itype = (inp.get("type") or "text").lower()
        if itype in ("text", "password", "email", "search", "url"):
            params[name] = payload
        elif itype == "hidden":
            params[name] = inp.get("value", "")
        elif itype in ("submit", "button"):
            params[name] = inp.get("value", "submit")
    for textarea in form.find_all("textarea"):
        name = textarea.get("name")
        if name:
            params[name] = payload
    for select in form.find_all("select"):
        name = select.get("name")
        if name:
            option = select.find("option")
            params[name] = option.get("value", "") if option else ""
    return params


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Détecte les vulnérabilités XSS reflected via paramètres GET et formulaires.
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

    for param_name, orig_values in url_params.items():
        for payload in XSS_PAYLOADS:
            test = dict(url_params)
            test[param_name] = [payload]
            new_query = urllib.parse.urlencode(test, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            try:
                time.sleep(DELAY)
                res = session.get(test_url, timeout=TIMEOUT)
                if _is_reflected(res.text, payload):
                    findings.append({
                        "type": "XSS_REFLECTED",
                        "severity": "high",
                        "url": url,
                        "detail": f"XSS Reflected détecté sur le paramètre GET '{param_name}'.",
                        "evidence": f"Payload reflété : {payload[:80]}",
                    })
                    break  # Passer au paramètre suivant
            except Exception:
                pass

    #Formulaires HTML
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        target_url = urllib.parse.urljoin(url, action)
        found = False

        for payload in XSS_PAYLOADS:
            params = _extract_form_params(form, payload)
            if not params:
                break
            try:
                time.sleep(DELAY)
                if method == "POST":
                    res = session.post(target_url, data=params, timeout=TIMEOUT)
                else:
                    res = session.get(target_url, params=params, timeout=TIMEOUT)

                if _is_reflected(res.text, payload):
                    findings.append({
                        "type": "XSS_REFLECTED",
                        "severity": "high",
                        "url": target_url,
                        "detail": f"XSS Reflected détecté dans le formulaire {method} (action: '{action}').",
                        "evidence": f"Payload reflété : {payload[:80]}",
                    })
                    found = True
                    break
            except Exception:
                pass
        if found:
            break

    return findings
