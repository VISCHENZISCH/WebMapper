#!/usr/bin/env python3
# coding:utf-8
import os
import json
import re
import urllib.parse
import requests
from utils import obfuscate_payload

# Répertoire des règles JSON déclaratives
RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


def load_rules() -> list[dict]:
    rules = []
    if not os.path.isdir(RULES_DIR):
        return rules
    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".json"):
            path = os.path.join(RULES_DIR, filename)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    rule = json.load(f)
                    if "name" in rule and "requests" in rule:
                        rules.append(rule)
            except Exception:
                pass
    return rules


def match_response(res: requests.Response, matcher: dict) -> bool:
    part = matcher.get("part", "body").lower()
    part_val = ""
    
    if part == "body":
        part_val = res.text
    elif part == "headers":
        part_val = "\n".join(f"{k}: {v}" for k, v in res.headers.items())
    elif part == "status":
        part_val = str(res.status_code)

    m_type = matcher.get("type", "word").lower()
    condition = matcher.get("condition", "or").lower()

    if m_type == "status":
        expected_status = matcher.get("status")
        if isinstance(expected_status, list):
            return res.status_code in expected_status
        return res.status_code == expected_status

    elif m_type == "word":
        words = matcher.get("words", [])
        if not words:
            return False
        if condition == "and":
            return all(w.lower() in part_val.lower() for w in words)
        return any(w.lower() in part_val.lower() for w in words)

    elif m_type == "regex":
        patterns = matcher.get("regex", [])
        if not patterns:
            return False
        matches = []
        for pat in patterns:
            try:
                if re.search(pat, part_val, re.IGNORECASE):
                    matches.append(pat)
            except Exception:
                pass
        if condition == "and":
            return len(matches) == len(patterns)
        return len(matches) > 0

    return False


def scan(url: str, session: requests.Session) -> list[dict]:
    findings = []
    rules = load_rules()
    if not rules:
        return []

    for rule in rules:
        severity = rule.get("severity", "info").lower()
        vuln_type = rule.get("type", "DECLARATIVE_VULN")
        detail_tpl = rule.get("detail", "Vulnérabilité détectée.")

        for req_def in rule.get("requests", []):
            method = req_def.get("method", "GET").upper()
            path_suffix = req_def.get("path", "")

            # Résolution de l'URL cible
            parsed_url = urllib.parse.urlparse(url)
            if path_suffix.startswith("/"):
                target_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path_suffix}"
            else:
                target_url = urllib.parse.urljoin(url, path_suffix)

            headers = req_def.get("headers", {})
            body = req_def.get("body", None)

            if body and isinstance(body, str):
                body = obfuscate_payload(body)

            try:
                if method == "POST":
                    res = session.post(target_url, headers=headers, data=body, timeout=10)
                else:
                    res = session.get(target_url, headers=headers, params=body, timeout=10)

                matchers = req_def.get("matchers", [])
                if not matchers:
                    continue

                matched_all = True
                matched_evidence = []
                for matcher in matchers:
                    if match_response(res, matcher):
                        m_info = f"type={matcher.get('type')}, part={matcher.get('part')}"
                        matched_evidence.append(m_info)
                    else:
                        matched_all = False
                        break

                if matched_all:
                    findings.append({
                        "type": vuln_type,
                        "severity": severity,
                        "url": target_url,
                        "detail": detail_tpl.format(url=target_url),
                        "evidence": " | ".join(matched_evidence),
                    })
                    # S'arrêter au premier match pour cette règle afin d'éviter le bruit
                    break
            except Exception:
                pass

    return findings
