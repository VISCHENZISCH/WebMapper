#!/usr/bin/env python3
# coding:utf-8
import json as json_lib
from datetime import datetime


def generate(data: dict, filepath: str):
    """Génère un rapport au format de standardisation CI/CD SARIF v2.1.0."""
    findings = data.get("findings", [])
    
    # Mapper les sévérités WebMapper vers les niveaux SARIF
    # Levels valides dans SARIF : "error", "warning", "note", "none"
    severity_mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note"
    }

    results = []
    rules_seen = {}
    
    for f in findings:
        rule_id = f.get("type", "UNKNOWN_VULN")
        severity = f.get("severity", "info").lower()
        level = severity_mapping.get(severity, "note")
        
        # Enregistrer la règle si elle n'a pas encore été déclarée dans la section rules de l'outil
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "shortDescription": {
                    "text": f"Vulnérabilité {rule_id.replace('_', ' ').title()}"
                }
            }
            
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f.get("detail", "Pas de détail fourni.")
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.get("url", "")
                        }
                    }
                }
            ],
            "properties": {
                "evidence": f.get("evidence", "")
            }
        })

    sarif_output = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "WebMapper",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/VISCHENZISCH/WebMapper",
                        "rules": list(rules_seen.values())
                    }
                },
                "results": results
            }
        ]
    }

    with open(filepath, "w", encoding="utf-8") as fh:
        json_lib.dump(sarif_output, fh, ensure_ascii=False, indent=2)
