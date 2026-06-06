#!/usr/bin/env python3
# coding:utf-8
"""
Module d'audit de sécurité des cookies — refactorisé selon la nouvelle convention.
Expose : scan(url, session) -> list[dict]
"""
import re
import time
import requests

DELAY = 0.5
TIMEOUT = 10

# Noms de cookies considérés comme sensibles
SENSITIVE_PATTERNS = ["session", "token", "auth", "jwt", "sid", "csrf", "login", "key", "secret"]


def _parse_set_cookie_headers(response) -> dict:
    """
    Extrait les flags HttpOnly / SameSite / Secure directement depuis les headers bruts.
    Retourne un dict { cookie_name -> {"httponly": bool, "samesite": str|None, "secure": bool} }
    """
    flags_map = {}
    raw_headers = []

    if hasattr(response, "raw") and hasattr(response.raw, "headers"):
        if hasattr(response.raw.headers, "getlist"):
            raw_headers = response.raw.headers.getlist("Set-Cookie")
        elif hasattr(response.raw.headers, "get_all"):
            raw_headers = response.raw.headers.get_all("Set-Cookie")

    for header in raw_headers:
        parts = [p.strip() for p in header.split(";")]
        if not parts:
            continue
        name_value = parts[0].split("=", 1)
        if len(name_value) < 2:
            continue
        cookie_name = name_value[0].strip()
        h_lower = header.lower()

        samesite = None
        m = re.search(r"samesite=(\w+)", h_lower)
        if m:
            samesite = m.group(1).capitalize()

        flags_map[cookie_name] = {
            "httponly": "httponly" in h_lower,
            "samesite": samesite,
            "secure":   "secure" in h_lower,
        }

    return flags_map


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Audite les cookies de session : flags Secure, HttpOnly, SameSite.
    """
    findings = []
    time.sleep(DELAY)

    try:
        response = session.get(url, timeout=TIMEOUT)
    except Exception as exc:
        return [{
            "type": "COOKIES_ANALYSIS_ERROR",
            "severity": "info",
            "url": url,
            "detail": f"Impossible d'analyser les cookies : {exc}",
            "evidence": "",
        }]

    flags_map = _parse_set_cookie_headers(response)

    if not session.cookies:
        return [{
            "type": "COOKIES_INFO",
            "severity": "info",
            "url": url,
            "detail": "Aucun cookie détecté sur cette URL.",
            "evidence": "",
        }]

    for cookie in session.cookies:
        name = cookie.name
        is_sensitive = any(p in name.lower() for p in SENSITIVE_PATTERNS)

        # Récupération des flags depuis les headers bruts (prioritaire)
        flags = flags_map.get(name, {})
        httponly = flags.get("httponly", False)
        samesite = flags.get("samesite", None)
        secure   = flags.get("secure", bool(cookie.secure))

        # Fallback sur _rest si les headers bruts n'ont rien donné
        if not httponly and hasattr(cookie, "_rest"):
            rest_lower = {k.lower(): v for k, v in cookie._rest.items()}
            httponly = "httponly" in rest_lower
            if not samesite:
                raw_ss = rest_lower.get("samesite")
                samesite = raw_ss.capitalize() if raw_ss else None

        base_evidence = (
            f"Cookie: {name} | Secure: {secure} | "
            f"HttpOnly: {httponly} | SameSite: {samesite or 'absent'} | Sensible: {is_sensitive}"
        )

        if not secure:
            findings.append({
                "type": "COOKIE_MISSING_SECURE_FLAG",
                "severity": "high" if is_sensitive else "medium",
                "url": url,
                "detail": f"Cookie '{name}' sans flag Secure — transmis en clair sur HTTP.",
                "evidence": base_evidence,
            })

        if not httponly:
            findings.append({
                "type": "COOKIE_MISSING_HTTPONLY_FLAG",
                "severity": "high" if is_sensitive else "medium",
                "url": url,
                "detail": f"Cookie '{name}' sans flag HttpOnly — accessible via JavaScript (risque XSS).",
                "evidence": base_evidence,
            })

        if not samesite:
            findings.append({
                "type": "COOKIE_MISSING_SAMESITE_FLAG",
                "severity": "medium",
                "url": url,
                "detail": f"Cookie '{name}' sans flag SameSite — vulnérable aux attaques CSRF.",
                "evidence": base_evidence,
            })
        elif samesite.lower() == "none" and not secure:
            findings.append({
                "type": "COOKIE_SAMESITE_NONE_WITHOUT_SECURE",
                "severity": "high",
                "url": url,
                "detail": f"Cookie '{name}' : SameSite=None sans Secure est invalide (RFC 6265bis).",
                "evidence": base_evidence,
            })

    return findings
