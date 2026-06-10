#!/usr/bin/env python3
# coding:utf-8
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# modules/info/cookies.py — Module d'audit de sécurité des cookies.
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
from __future__ import annotations

import base64
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Final

import requests

logger = logging.getLogger("webmapper.cookies")

DELAY: Final[float] = 0.5
TIMEOUT: Final[int] = 10

# Noms de cookies considérés comme sensibles
SENSITIVE_PATTERNS: Final[tuple[str, ...]] = (
    "session", "token", "auth", "jwt", "sid", "csrf", "login", 
    "key", "secret", "phpsessid", "jsessionid", "cf_clearance"
)

# Regex pour détecter un JWT basique (header.payload.signature)
JWT_REGEX: Final[re.Pattern] = re.compile(r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$")


@dataclass(slots=True)
class CookieProps:
    """Propriétés extraites d'un cookie."""
    name: str
    value: str
    domain: str
    path: str
    httponly: bool = False
    secure: bool = False
    samesite: str | None = None
    expires: str | None = None
    max_age: str | None = None
    is_session: bool = True
    is_sensitive: bool = False
    is_jwt: bool = False


def _is_base64_encoded_json(value: str) -> bool:
    """Tente de décoder en Base64 puis de parser en JSON."""
    try:
        # Pad string if necessary
        padded = value + '=' * (-len(value) % 4)
        decoded = base64.b64decode(padded).decode('utf-8')
        json.loads(decoded)
        return True
    except Exception:
        return False


def _parse_set_cookie_headers(response: requests.Response) -> dict[str, CookieProps]:
    """Parse les en-têtes Set-Cookie bruts pour obtenir les propriétés exactes.
    
    Retourne un dict {cookie_name: CookieProps}.
    """
    props_map = {}
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
        cookie_val = name_value[1].strip()
        h_lower = header.lower()

        samesite = None
        m_ss = re.search(r"samesite=([a-z]+)", h_lower)
        if m_ss:
            samesite = m_ss.group(1).capitalize()

        expires = None
        m_exp = re.search(r"expires=([^;]+)", h_lower)
        if m_exp:
            expires = m_exp.group(1)

        max_age = None
        m_ma = re.search(r"max-age=([^;]+)", h_lower)
        if m_ma:
            max_age = m_ma.group(1)

        # Si pas d'expires ni max-age, c'est un cookie de session (détruit à la fermeture du navigateur)
        is_session = not (expires or max_age)
        
        is_sensitive = any(p in cookie_name.lower() for p in SENSITIVE_PATTERNS)
        is_jwt = bool(JWT_REGEX.match(cookie_val)) or _is_base64_encoded_json(cookie_val)

        props_map[cookie_name] = CookieProps(
            name=cookie_name,
            value=cookie_val,
            domain="", # À enrichir si besoin
            path="",
            httponly="httponly" in h_lower,
            secure="secure" in h_lower,
            samesite=samesite,
            expires=expires,
            max_age=max_age,
            is_session=is_session,
            is_sensitive=is_sensitive,
            is_jwt=is_jwt
        )

    return props_map


def scan(url: str, session: requests.Session) -> list[dict]:
    """Audit approfondi des cookies de session et de suivi."""
    findings: list[dict] = []
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

    # Parser les headers bruts pour avoir les vraies valeurs configurées par le serveur
    props_map = _parse_set_cookie_headers(response)

    if not session.cookies and not props_map:
        return [{
            "type": "COOKIES_INFO",
            "severity": "info",
            "url": url,
            "detail": "Aucun cookie détecté sur cette URL.",
            "evidence": "",
        }]

    # Si certains cookies existent dans session.cookies mais n'étaient pas dans Set-Cookie 
    # (car ajoutés avant ou par d'autres requêtes), on les intègre.
    for cookie in session.cookies:
        if cookie.name not in props_map:
            is_sensitive = any(p in cookie.name.lower() for p in SENSITIVE_PATTERNS)
            is_jwt = bool(JWT_REGEX.match(cookie.value)) or _is_base64_encoded_json(cookie.value)
            
            # Reconstruire les propriétés via cookie._rest si disponible
            httponly = False
            samesite = None
            if hasattr(cookie, "_rest"):
                rest_lower = {k.lower(): v for k, v in cookie._rest.items()}
                httponly = "httponly" in rest_lower
                raw_ss = rest_lower.get("samesite")
                samesite = raw_ss.capitalize() if raw_ss else None

            props_map[cookie.name] = CookieProps(
                name=cookie.name,
                value=cookie.value,
                domain=cookie.domain,
                path=cookie.path,
                httponly=httponly,
                secure=cookie.secure,
                samesite=samesite,
                is_session=cookie.expires is None,
                is_sensitive=is_sensitive,
                is_jwt=is_jwt
            )

    # Analyse de chaque cookie
    for name, props in props_map.items():
        base_evidence = (
            f"Cookie: {name} | Secure: {props.secure} | HttpOnly: {props.httponly} | "
            f"SameSite: {props.samesite or 'Absent'} | Sensible: {props.is_sensitive}"
        )

        # 1. Flags manquants
        if not props.secure:
            findings.append({
                "type": "COOKIE_MISSING_SECURE_FLAG",
                "severity": "high" if props.is_sensitive else "medium",
                "url": url,
                "detail": f"Cookie '{name}' sans flag Secure — transmissible en clair sur HTTP.",
                "evidence": base_evidence,
            })

        if not props.httponly:
            findings.append({
                "type": "COOKIE_MISSING_HTTPONLY_FLAG",
                "severity": "high" if props.is_sensitive else "medium",
                "url": url,
                "detail": f"Cookie '{name}' sans flag HttpOnly — accessible via JavaScript (risque d'exfiltration en cas de XSS).",
                "evidence": base_evidence,
            })

        if not props.samesite:
            findings.append({
                "type": "COOKIE_MISSING_SAMESITE_FLAG",
                "severity": "medium",
                "url": url,
                "detail": f"Cookie '{name}' sans flag SameSite — potentiellement vulnérable aux attaques CSRF.",
                "evidence": base_evidence,
            })
        elif props.samesite.lower() == "none" and not props.secure:
            findings.append({
                "type": "COOKIE_SAMESITE_NONE_WITHOUT_SECURE",
                "severity": "high",
                "url": url,
                "detail": f"Cookie '{name}' avec SameSite=None mais sans Secure — invalide selon RFC 6265bis.",
                "evidence": base_evidence,
            })

        # 2. Analyse des types de session et durées de vie
        if props.is_sensitive and not props.is_session:
            findings.append({
                "type": "COOKIE_PERSISTENT_SESSION",
                "severity": "medium",
                "url": url,
                "detail": f"Cookie sensible '{name}' persistant. Les cookies d'authentification/session devraient expirer à la fermeture du navigateur (Session cookie).",
                "evidence": f"Expires: {props.expires} | Max-Age: {props.max_age}",
            })

        if props.is_jwt and not props.httponly:
            findings.append({
                "type": "COOKIE_JWT_WITHOUT_HTTPONLY",
                "severity": "high",
                "url": url,
                "detail": f"Cookie '{name}' contient un JWT (JSON Web Token) accessible en JavaScript. Très risqué en cas de XSS.",
                "evidence": f"Valeur (tronquée) : {props.value[:30]}...",
            })

    return findings
