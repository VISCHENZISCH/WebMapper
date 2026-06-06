#!/usr/bin/env python3
# coding:utf-8
import os
import shutil
from datetime import datetime
from .formatter import ResultFormatter
from .templates import json as tpl_json
from .templates import html as tpl_html
from .templates import csv as tpl_csv
from .templates import sarif as tpl_sarif


class Reporter:
    output_dir = "OUTPUT/reports"

    @staticmethod
    def generate_all(findings: list[dict], scan_type: str = "scan") -> dict:
        """
        Génère les rapports HTML, JSON, CSV et SARIF à partir de la liste de findings.

        :param findings:  Liste de findings (format unifié)
        :param scan_type: Préfixe du nom de fichier (ex: full_scan, vuln_scan)
        :return:          Dictionnaire des chemins de fichiers générés
        """
        os.makedirs(Reporter.output_dir, exist_ok=True)

        data = ResultFormatter.to_generic_dict(findings)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = f"{scan_type}-{timestamp}"

        paths = {}

        # JSON
        json_path = os.path.join(Reporter.output_dir, f"{base}.json")
        tpl_json.generate(data, json_path)
        shutil.copy2(json_path, os.path.join(Reporter.output_dir, "latest_report.json"))
        paths["json"] = json_path

        # HTML
        html_path = os.path.join(Reporter.output_dir, f"{base}.html")
        tpl_html.generate(data, html_path)
        shutil.copy2(html_path, os.path.join(Reporter.output_dir, "latest_report.html"))
        paths["html"] = html_path

        # CSV
        csv_path = os.path.join(Reporter.output_dir, f"{base}.csv")
        tpl_csv.generate(data, csv_path)
        shutil.copy2(csv_path, os.path.join(Reporter.output_dir, "latest_report.csv"))
        paths["csv"] = csv_path

        # SARIF
        sarif_path = os.path.join(Reporter.output_dir, f"{base}.sarif")
        tpl_sarif.generate(data, sarif_path)
        shutil.copy2(sarif_path, os.path.join(Reporter.output_dir, "latest_report.sarif"))
        paths["sarif"] = sarif_path

        paths["latest_html"] = os.path.join(Reporter.output_dir, "latest_report.html")
        return paths
