#!/usr/bin/env python3
# coding:utf-8
"""
Module de détection de l'absence de protection CSRF.

Logique de détection :
  - Analyse les formulaires HTML qui utilisent la méthode POST
  - Vérifie la présence d'un token CSRF (champ caché ou header)
  - Vérifie également le flag SameSite des cookies de session
"""
import re
import time
import requests
from bs4 import BeautifulSoup

DELAY = 0.5
TIMEOUT = 10

# Noms courants des tokens CSRF dans les formulaires
CSRF_TOKEN_NAMES = {
    "csrf_token", "csrf", "_csrf", "_token", "csrftoken",
    "__requestverificationtoken", "authenticity_token",
    "_csrf_token", "xsrf_token", "anti_csrf", "form_token",
    "csrfmiddlewaretoken",  # Django
    "struts.token",         # Apache Struts
    "javax.faces.viewstate", # JSF
}

# Noms courants des cookies de session
SESSION_COOKIE_NAMES = {
    "sessionid", "session", "phpsessid", "jsessionid",
    "asp.net_sessionid", "connect.sid", "sid", "auth",
}


def _has_csrf_token(form) -> tuple[bool, str]:
    """
    Vérifie si le formulaire contient un champ de token CSRF.
    Retourne (token_présent, nom_du_champ_ou_vide).
    """
    for inp in form.find_all("input", type="hidden"):
        name = (inp.get("name") or "").lower()
        if name in CSRF_TOKEN_NAMES:
            return True, inp.get("name", "")
    return False, ""


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Détecte l'absence de protection CSRF sur les formulaires POST.
    """
    findings = []
    time.sleep(DELAY)

    try:
        response = session.get(url, timeout=TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception:
        return []

    #Analyse des formulaires POST 
    post_forms = [f for f in soup.find_all("form")
                  if (f.get("method") or "GET").upper() == "POST"]

    for form in post_forms:
        action = form.get("action", url)
        has_token, token_name = _has_csrf_token(form)

        if not has_token:
            # Vérifier s'il y a un champ password ou email → formulaire sensible
            sensitive = any(
                (inp.get("type") or "").lower() in ("password", "email")
                for inp in form.find_all("input")
            )
            severity = "high" if sensitive else "medium"
            findings.append({
                "type": "CSRF_NO_TOKEN_IN_FORM",
                "severity": severity,
                "url": url,
                "detail": (
                    f"Formulaire POST sans token CSRF détecté (action : '{action}'). "
                    "Un attaquant peut forcer un utilisateur authentifié à soumettre ce formulaire à son insu."
                    + (" Ce formulaire semble sensible (mot de passe / email)." if sensitive else "")
                ),
                "evidence": (
                    f"Action: {action} | "
                    f"Champs: {[i.get('name') for i in form.find_all('input') if i.get('name')]}"
                ),
            })

    #Vérification SameSite sur les cookies de session 
    try:
        # Récupère les cookies bruts depuis les headers pour analyser SameSite
        raw_cookies = response.headers.get("Set-Cookie", "")
        for cookie in session.cookies:
            if cookie.name.lower() not in SESSION_COOKIE_NAMES:
                continue

            # Lire SameSite depuis _rest (attributs non-standard requests)
            samesite = None
            if hasattr(cookie, "_rest"):
                rest_lower = {k.lower(): v for k, v in cookie._rest.items()}
                samesite = rest_lower.get("samesite")

            if not samesite or samesite.lower() == "none":
                findings.append({
                    "type": "CSRF_SESSION_COOKIE_NO_SAMESITE",
                    "severity": "medium",
                    "url": url,
                    "detail": (
                        f"Cookie de session '{cookie.name}' sans flag SameSite (ou SameSite=None). "
                        "Ce cookie sera envoyé lors de requêtes cross-site, facilitant les attaques CSRF."
                    ),
                    "evidence": (
                        f"Cookie: {cookie.name} | Secure: {cookie.secure} | "
                        f"SameSite: {samesite or 'absent'}"
                    ),
                })

    except Exception:
        pass

    return findings
