#!/usr/bin/env python3
# coding:utf-8
"""
Expose : scan(url, session) -> list[dict]

Logique :
  - Error-based : injecter ' dans chaque paramètre GET/formulaire et chercher des erreurs SQL
  - Tester à la fois les formulaires et les paramètres URL
"""
import time
import random
import urllib.parse
import requests
from bs4 import BeautifulSoup

DELAY = 0.5
TIMEOUT = 10

SQLI_PAYLOADS = ["'", "''", "' OR '1'='1", "' OR 1=1--", "1' ORDER BY 1--"]

# Signatures d'erreurs de base de données
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql_fetch_array()",
    "unclosed quotation mark",
    "postgresql query failed",
    "sqlserver exception",
    "ora-01756", "ora-00907", "oracle error",
    "syntax error", "quoted string not properly terminated",
    "mysql_num_rows()", "pg_query()",
    "sqlite3.operationalerror", "microsoft ole db provider for sql server",
]


def _is_sqli(text: str) -> str | None:
    """Retourne la signature détectée ou None."""
    lower = text.lower()
    for sig in ERROR_SIGNATURES:
        if sig in lower:
            return sig
    return None


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Détecte les injections SQL error-based via paramètres GET et formulaires.
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

    for payload in SQLI_PAYLOADS:
        for param_name in url_params:
            test = {k: (v[0] + payload) for k, v in url_params.items()}
            try:
                time.sleep(DELAY)
                res = session.get(url, params=test, timeout=TIMEOUT)
                sig = _is_sqli(res.text)
                if sig:
                    findings.append({
                        "type": "SQL_INJECTION_ERROR_BASED",
                        "severity": "critical",
                        "url": url,
                        "detail": f"Injection SQL détectée sur le paramètre GET '{param_name}'.",
                        "evidence": f"Signature : '{sig}' | Payload : {payload}",
                    })
                    return findings
            except Exception:
                pass

    #Formulaires HTML
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        target_url = urllib.parse.urljoin(url, action)

        # Construction des paramètres avec le payload
        payload = random.choice(SQLI_PAYLOADS)
        form_data = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype in ("text", "password", "email", "search"):
                form_data[name] = payload
            else:
                form_data[name] = inp.get("value", "")

        if not form_data:
            continue

        try:
            time.sleep(DELAY)
            if method == "POST":
                res = session.post(target_url, data=form_data, timeout=TIMEOUT)
            else:
                res = session.get(target_url, params=form_data, timeout=TIMEOUT)
            sig = _is_sqli(res.text)
            if sig:
                findings.append({
                    "type": "SQL_INJECTION_ERROR_BASED",
                    "severity": "critical",
                    "url": target_url,
                    "detail": f"Injection SQL détectée sur le formulaire {method} (action: '{action}').",
                    "evidence": f"Signature : '{sig}' | Payload : {payload}",
                })
                return findings
        except Exception:
            pass

    return findings
