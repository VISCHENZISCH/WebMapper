#!/usr/bin/env python3
# coding:utf-8
import csv as csv_lib


def generate(data: dict, filepath: str):
    """Génère un rapport CSV à partir des findings unifiés."""
    findings = data.get("findings", [])

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv_lib.writer(fh)
        # En-tête
        writer.writerow(["Sévérité", "Type", "URL", "Détail", "Preuve"])
        # Données
        for f in findings:
            writer.writerow([
                f.get("severity", ""),
                f.get("type", ""),
                f.get("url", ""),
                f.get("detail", ""),
                f.get("evidence", ""),
            ])
