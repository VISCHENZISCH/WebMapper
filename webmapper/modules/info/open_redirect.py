#!/usr/bin/env python3
# coding:utf-8
"""
Logique de détection :
  - Identifie les paramètres d'URL dont le nom suggère une redirection
    (redirect, url, next, return, to, dest, target, link, …)
  - Injecte https://evil-attacker.com et envoie la requête sans suivre les redirections
  - Détection si le header Location pointe vers l'URL malveillante
"""
import time
import urllib.parse
import requests
from bs4 import BeautifulSoup

DELAY = 0.5
TIMEOUT = 10

EVIL_URL = "https://evil-attacker.com"

# Noms de paramètres suspects associés aux redirections
REDIRECT_PARAMS = {
    "redirect", "url", "next", "return", "returnto", "return_to",
    "to", "dest", "destination", "target", "goto", "link",
    "forward", "redir", "redirect_url", "redirect_uri",
    "back", "continue", "location",
}


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Détecte les Open Redirects via paramètres GET et formulaires.
    Les redirections NE sont PAS suivies (allow_redirects=False).
    """
    findings = []
    time.sleep(DELAY)

    #Paramètres GET dans l'URL
    parsed = urllib.parse.urlparse(url)
    url_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    for param_name in url_params:
        if param_name.lower() not in REDIRECT_PARAMS:
            continue

        test_params = dict(url_params)
        test_params[param_name] = [EVIL_URL]
        new_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()

        time.sleep(DELAY)
        try:
            res = session.get(test_url, timeout=TIMEOUT, allow_redirects=False)
            location = res.headers.get("Location", "")
            if EVIL_URL in location or "evil-attacker" in location:
                findings.append({
                    "type": "OPEN_REDIRECT",
                    "severity": "medium",
                    "url": url,
                    "detail": (
                        f"Open Redirect détecté sur le paramètre GET '{param_name}'. "
                        "Un attaquant peut rediriger les victimes vers un site malveillant "
                        "en partageant un lien d'apparence légitime."
                    ),
                    "evidence": f"Paramètre : {param_name} | Location: {location} | Status: {res.status_code}",
                })
                return findings  # Un finding par URL suffit
        except Exception:
            pass

    #Formulaires HTML
    try:
        response = session.get(url, timeout=TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception:
        return findings

    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        target_url = urllib.parse.urljoin(url, action)

        for inp in form.find_all("input"):
            name = inp.get("name", "")
            if name.lower() not in REDIRECT_PARAMS:
                continue

            # Collecte de tous les champs du formulaire
            form_data = {}
            for field in form.find_all("input"):
                fname = field.get("name")
                if fname:
                    form_data[fname] = field.get("value", "test")
            form_data[name] = EVIL_URL

            time.sleep(DELAY)
            try:
                if method == "POST":
                    res = session.post(target_url, data=form_data,
                                       timeout=TIMEOUT, allow_redirects=False)
                else:
                    res = session.get(target_url, params=form_data,
                                      timeout=TIMEOUT, allow_redirects=False)

                location = res.headers.get("Location", "")
                if EVIL_URL in location or "evil-attacker" in location:
                    findings.append({
                        "type": "OPEN_REDIRECT",
                        "severity": "medium",
                        "url": target_url,
                        "detail": (
                            f"Open Redirect détecté sur le champ '{name}' "
                            f"du formulaire {method}."
                        ),
                        "evidence": f"Champ : {name} | Location: {location} | Status: {res.status_code}",
                    })
                    return findings
            except Exception:
                pass

    return findings
