# Expose : scan(url, session) -> list[dict]
"""
Module de détection d'injection de commandes OS (Command Injection).

Logique de détection :
  - Time-based : injecter des payloads avec délai (sleep/ping) et mesurer la latence
  - Error-based : rechercher des signatures d'output OS dans la réponse
  - Tester chaque champ individuellement (y compris hidden)
  - Tester les en-têtes HTTP
"""
import time
import logging
import urllib.parse
import requests
from bs4 import BeautifulSoup
from utils import extract_form_fields

logger = logging.getLogger("webmapper.cmdi")

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

# Signatures d'erreur shell ou output OS
ERROR_SIGNATURES = [
    "root:x:", "root:0:0", "daemon:", "nobody:", "www-data",  # /etc/passwd
    "administrator", "nt authority",                           # Windows
    "sh:", "bash:", "/bin/sh", "/bin/bash",
    "command not found", "is not recognized as an internal",
]


def _send(session, method, url, params) -> tuple[str, float]:
    """Envoie une requête et retourne (texte_réponse, durée_secondes)."""
    start = time.time()
    try:
        if method == "POST":
            res = session.post(url, data=params, timeout=TIMEOUT + 7)
        else:
            res = session.get(url, params=params, timeout=TIMEOUT + 7)
        return res.text, time.time() - start
    except Exception as exc:
        logger.debug("Erreur réseau %s %s : %s", method, url, exc)
        return "", time.time() - start


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Détecte les vulnérabilités Command Injection via paramètres GET, formulaires et en-têtes.
    """
    findings = []
    seen = set()

    def add_finding(f):
        key = (f["type"], f.get("url"), f.get("evidence", "")[:40])
        if key not in seen:
            seen.add(key)
            findings.append(f)

    # Récupération de la page originale
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
        # 1.1 Time-based sur chaque paramètre
        for payload, delay in TIME_PAYLOADS:
            test = {k: (v[0] + payload if k == param_name else v[0]) for k, v in url_params.items()}
            _, elapsed = _send(session, "GET", url, test)
            time.sleep(DELAY)
            if elapsed >= delay:
                add_finding({
                    "type": "COMMAND_INJECTION_TIME_BASED",
                    "severity": "critical",
                    "url": url,
                    "detail": f"Injection de commande OS (Time-based) détectée sur le paramètre GET '{param_name}'.",
                    "evidence": f"Délai observé : {elapsed:.1f}s (attendu ≥ {delay}s) | Payload : {payload}",
                })

        # 1.2 Error-based sur chaque paramètre
        for payload in ERROR_PAYLOADS:
            test = {k: (v[0] + payload if k == param_name else v[0]) for k, v in url_params.items()}
            text, _ = _send(session, "GET", url, test)
            time.sleep(DELAY)
            for sig in ERROR_SIGNATURES:
                if sig in text.lower():
                    add_finding({
                        "type": "COMMAND_INJECTION_ERROR_BASED",
                        "severity": "critical",
                        "url": url,
                        "detail": f"Injection de commande OS (Error-based) détectée sur le paramètre GET '{param_name}'.",
                        "evidence": f"Signature : '{sig}' | Payload : {payload}",
                    })

    # 2. Formulaires HTML - helper partagé
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        target_url = urllib.parse.urljoin(url, action)

        template, injectable_names = extract_form_fields(form, include_hidden=True)

        if not injectable_names:
            continue

        # Tester chaque champ individuellement
        for field_name in injectable_names:
            original_val = template[field_name]

            # 2.1 Time-based sur champ formulaire
            for payload, delay in TIME_PAYLOADS[:3]:
                test = template.copy()
                test[field_name] = original_val + payload
                _, elapsed = _send(session, method, target_url, test)
                time.sleep(DELAY)
                if elapsed >= delay:
                    add_finding({
                        "type": "COMMAND_INJECTION_TIME_BASED",
                        "severity": "critical",
                        "url": target_url,
                        "detail": f"Injection de commande OS (Time-based) détectée sur le champ '{field_name}' du formulaire ({method}).",
                        "evidence": f"Délai : {elapsed:.1f}s | Payload : {payload}",
                    })

            # 2.2 Error-based sur champ formulaire
            for payload in ERROR_PAYLOADS[:3]:
                test = template.copy()
                test[field_name] = original_val + payload
                text, _ = _send(session, method, target_url, test)
                time.sleep(DELAY)
                for sig in ERROR_SIGNATURES:
                    if sig in text.lower():
                        add_finding({
                            "type": "COMMAND_INJECTION_ERROR_BASED",
                            "severity": "critical",
                            "url": target_url,
                            "detail": f"Injection de commande OS (Error-based) détectée sur le champ '{field_name}' du formulaire ({method}).",
                            "evidence": f"Signature : '{sig}' | Payload : {payload}",
                        })

    # 3. Injection d'en-têtes HTTP
    target_headers = ["X-Forwarded-For", "User-Agent", "Referer"]
    for header in target_headers:
        # Time-based sur en-têtes
        for payload, delay in TIME_PAYLOADS[:2]:
            try:
                time.sleep(DELAY)
                start = time.time()
                session.get(url, headers={header: payload}, timeout=TIMEOUT + 7)
                elapsed = time.time() - start
                if elapsed >= delay:
                    add_finding({
                        "type": "COMMAND_INJECTION_HEADER_TIME_BASED",
                        "severity": "critical",
                        "url": url,
                        "detail": f"Injection de commande OS (Time-based) détectée via l'en-tête HTTP '{header}'.",
                        "evidence": f"Délai : {elapsed:.1f}s | Payload : {payload}",
                    })
            except Exception as exc:
                logger.debug("Erreur test cmdi header time-based '%s' : %s", header, exc)

        # Error-based sur en-têtes
        for payload in ERROR_PAYLOADS[:2]:
            try:
                time.sleep(DELAY)
                res = session.get(url, headers={header: payload}, timeout=TIMEOUT)
                for sig in ERROR_SIGNATURES:
                    if sig in res.text.lower():
                        add_finding({
                            "type": "COMMAND_INJECTION_HEADER_ERROR_BASED",
                            "severity": "critical",
                            "url": url,
                            "detail": f"Injection de commande OS (Error-based) détectée via l'en-tête HTTP '{header}'.",
                            "evidence": f"Signature : '{sig}' | Payload : {payload}",
                        })
            except Exception as exc:
                logger.debug("Erreur test cmdi header error-based '%s' : %s", header, exc)

    return findings
