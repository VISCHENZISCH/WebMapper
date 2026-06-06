#!/usr/bin/env python3
# coding:utf-8
"""
Formatter - convertit la liste de findings unifiés pour les exports.
"""


class ResultFormatter:

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    @staticmethod
    def to_generic_dict(findings: list[dict]) -> dict:
        """
        Trie les findings par sévérité et les classe par catégorie pour les templates.

        Format d'entrée attendu (par finding) :
          {
            "type":     str,
            "severity": "critical|high|medium|low|info",
            "url":      str,
            "detail":   str,
            "evidence": str,
          }
        """
        # Tri : du plus critique au moins critique
        sorted_findings = sorted(
            findings,
            key=lambda f: ResultFormatter.SEVERITY_ORDER.get(
                f.get("severity", "info").lower(), 4
            ),
        )

        # Compteurs par sévérité
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in sorted_findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        return {
            "findings":  sorted_findings,
            "summary":   counts,
            "total":     len(sorted_findings),
        }
