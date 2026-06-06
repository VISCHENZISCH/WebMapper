# Expose : scan(url, session) -> list[dict]
"""
Module de détection d'injection SQL.

Logique de détection :
  - Error-based : signatures d'erreurs de SGBD dans la réponse
  - Boolean-blind : analyse différentielle (condition vraie vs fausse)
  - Tester chaque champ individuellement (y compris hidden)
  - Injection d'en-têtes HTTP
"""
import time
import logging
import urllib.parse
import requests
from bs4 import BeautifulSoup
from utils import obfuscate_payload, calculate_similarity, extract_form_fields

logger = logging.getLogger("webmapper.sqli")

DELAY = 0.5
TIMEOUT = 10

SQLI_PAYLOADS = ["'", "''", "1' ORDER BY 1--"]

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


def _check_baseline_stability(session, url, timeout) -> tuple[str, bool]:
    """
    Vérifie la stabilité de la page en faisant 2 requêtes identiques.
    Retourne (baseline_text, is_stable).
    Une page est stable si deux requêtes identiques donnent > 0.95 de similarité.
    """
    try:
        res1 = session.get(url, timeout=timeout)
        time.sleep(0.3)
        res2 = session.get(url, timeout=timeout)
        similarity = calculate_similarity(res1.text, res2.text)
        is_stable = similarity > 0.95
        if not is_stable:
            logger.debug("Page instable (%s) — similarité naturelle: %.2f. Boolean-blind peu fiable.", url, similarity)
        return res1.text, is_stable
    except Exception:
        return "", False


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Détecte les injections SQL via paramètres GET, formulaires et en-têtes.
    Combine de l'error-based et de l'analyse différentielle (boolean-blind).
    """
    findings = []
    seen = set()

    def add_finding(f):
        key = (f["type"], f.get("url"), f.get("evidence", "")[:40])
        if key not in seen:
            seen.add(key)
            findings.append(f)

    # 1. Page originale / Baseline + vérification de stabilité
    time.sleep(DELAY)
    baseline_text, page_is_stable = _check_baseline_stability(session, url, TIMEOUT)
    if not baseline_text:
        return []

    try:
        soup = BeautifulSoup(baseline_text, "html.parser")
    except Exception as exc:
        logger.warning("Erreur parsing HTML %s : %s", url, exc)
        return []

    # 2. Paramètres GET dans l'URL
    parsed = urllib.parse.urlparse(url)
    url_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    for param_name in url_params:
        # 2.1 GET Error-based
        for payload in SQLI_PAYLOADS:
            obfuscated_payload = obfuscate_payload(payload, "sql_spaces")
            test = {k: (v[0] + obfuscated_payload if k == param_name else v[0]) for k, v in url_params.items()}
            try:
                time.sleep(DELAY)
                res = session.get(url, params=test, timeout=TIMEOUT)
                sig = _is_sqli(res.text)
                if sig:
                    add_finding({
                        "type": "SQL_INJECTION_ERROR_BASED",
                        "severity": "critical",
                        "url": url,
                        "detail": f"Injection SQL (Error-based) détectée sur le paramètre GET '{param_name}'.",
                        "evidence": f"Signature : '{sig}' | Payload : {payload}",
                    })
            except Exception as exc:
                logger.debug("Erreur test SQLi error-based param '%s' : %s", param_name, exc)

        # 2.2 GET Boolean-based blind (uniquement si la page est stable)
        if page_is_stable:
            true_payloads = ["' AND 1=1--", " AND 1=1", "' OR '1'='1"]
            false_payloads = ["' AND 1=2--", " AND 1=2", "' OR '1'='2"]

            for true_pay, false_pay in zip(true_payloads, false_payloads):
                try:
                    time.sleep(DELAY)
                    test_true = {k: (v[0] + obfuscate_payload(true_pay, "sql_spaces") if k == param_name else v[0]) for k, v in url_params.items()}
                    res_true = session.get(url, params=test_true, timeout=TIMEOUT)

                    time.sleep(DELAY)
                    test_false = {k: (v[0] + obfuscate_payload(false_pay, "sql_spaces") if k == param_name else v[0]) for k, v in url_params.items()}
                    res_false = session.get(url, params=test_false, timeout=TIMEOUT)

                    sim_true = calculate_similarity(baseline_text, res_true.text)
                    sim_false = calculate_similarity(baseline_text, res_false.text)

                    if sim_true > 0.90 and (sim_true - sim_false) > 0.08:
                        add_finding({
                            "type": "SQL_INJECTION_BOOLEAN_BLIND",
                            "severity": "critical",
                            "url": url,
                            "detail": f"Injection SQL aveugle (Boolean-blind) détectée sur le paramètre GET '{param_name}'.",
                            "evidence": f"Similitude Vraie : {sim_true:.2f} | Similitude Fausse : {sim_false:.2f}",
                        })
                except Exception as exc:
                    logger.debug("Erreur test SQLi blind param '%s' : %s", param_name, exc)

    # 3. Formulaires HTML — helper partagé
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        target_url = urllib.parse.urljoin(url, action)

        template, injectable_names = extract_form_fields(form, include_hidden=True)

        if not injectable_names:
            continue

        # Capturer la baseline du formulaire
        try:
            time.sleep(DELAY)
            if method == "POST":
                form_baseline_res = session.post(target_url, data=template, timeout=TIMEOUT)
            else:
                form_baseline_res = session.get(target_url, params=template, timeout=TIMEOUT)
            form_baseline_text = form_baseline_res.text
        except Exception:
            form_baseline_text = baseline_text

        # Tester chaque paramètre injectable individuellement
        for field_name in injectable_names:
            original_val = template[field_name]

            # 3.1 Formulaire Error-based
            for payload in SQLI_PAYLOADS:
                form_data = template.copy()
                form_data[field_name] = original_val + obfuscate_payload(payload, "sql_spaces")

                try:
                    time.sleep(DELAY)
                    if method == "POST":
                        res = session.post(target_url, data=form_data, timeout=TIMEOUT)
                    else:
                        res = session.get(target_url, params=form_data, timeout=TIMEOUT)
                    sig = _is_sqli(res.text)
                    if sig:
                        add_finding({
                            "type": "SQL_INJECTION_ERROR_BASED",
                            "severity": "critical",
                            "url": target_url,
                            "detail": f"Injection SQL détectée sur le formulaire {method} (champ : '{field_name}').",
                            "evidence": f"Signature : '{sig}' | Payload : {payload}",
                        })
                except Exception as exc:
                    logger.debug("Erreur test SQLi formulaire champ '%s' : %s", field_name, exc)

            # 3.2 Formulaire Boolean-based blind (uniquement si page stable)
            if page_is_stable:
                true_payloads = ["' AND 1=1--", " AND 1=1", "' OR '1'='1"]
                false_payloads = ["' AND 1=2--", " AND 1=2", "' OR '1'='2"]

                for true_pay, false_pay in zip(true_payloads, false_payloads):
                    try:
                        form_data_true = template.copy()
                        form_data_true[field_name] = original_val + obfuscate_payload(true_pay, "sql_spaces")

                        form_data_false = template.copy()
                        form_data_false[field_name] = original_val + obfuscate_payload(false_pay, "sql_spaces")

                        time.sleep(DELAY)
                        if method == "POST":
                            res_true = session.post(target_url, data=form_data_true, timeout=TIMEOUT)
                        else:
                            res_true = session.get(target_url, params=form_data_true, timeout=TIMEOUT)

                        time.sleep(DELAY)
                        if method == "POST":
                            res_false = session.post(target_url, data=form_data_false, timeout=TIMEOUT)
                        else:
                            res_false = session.get(target_url, params=form_data_false, timeout=TIMEOUT)

                        sim_true = calculate_similarity(form_baseline_text, res_true.text)
                        sim_false = calculate_similarity(form_baseline_text, res_false.text)

                        if sim_true > 0.90 and (sim_true - sim_false) > 0.08:
                            add_finding({
                                "type": "SQL_INJECTION_BOOLEAN_BLIND",
                                "severity": "critical",
                                "url": target_url,
                                "detail": f"Injection SQL aveugle (Boolean-blind) détectée sur le formulaire {method} (champ : '{field_name}').",
                                "evidence": f"Similitude Vraie : {sim_true:.2f} | Similitude Fausse : {sim_false:.2f}",
                            })
                    except Exception as exc:
                        logger.debug("Erreur test SQLi blind formulaire champ '%s' : %s", field_name, exc)

    # 4. Injection d'en-têtes HTTP (Headers injection)
    target_headers = ["X-Forwarded-For", "User-Agent", "Referer"]
    for header in target_headers:
        for payload in SQLI_PAYLOADS:
            try:
                time.sleep(DELAY)
                custom_headers = {header: obfuscate_payload(payload, "sql_spaces")}
                res = session.get(url, headers=custom_headers, timeout=TIMEOUT)
                sig = _is_sqli(res.text)
                if sig:
                    add_finding({
                        "type": "SQL_INJECTION_HEADER_ERROR_BASED",
                        "severity": "critical",
                        "url": url,
                        "detail": f"Injection SQL détectée via l'en-tête HTTP '{header}'.",
                        "evidence": f"Signature : '{sig}' | Payload : {payload}",
                    })
            except Exception as exc:
                logger.debug("Erreur test SQLi header '%s' : %s", header, exc)

    return findings
