import os
import shutil
from datetime import datetime
from .formatter import ResultFormatter
from .templates import json, html, csv

class Reporter:
    output_dir = "OUTPUT/reports"

    @staticmethod
    def generate_all(results, service_type="scan"):
        """
        Génère les rapports dans tous les formats disponibles.
        """
        if not os.path.exists(Reporter.output_dir):
            os.makedirs(Reporter.output_dir)

        data = ResultFormatter.to_generic_dict(results)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base_filename = f"{service_type}-{timestamp}"

        # JSON
        json_path = os.path.join(Reporter.output_dir, f"{base_filename}.json")
        json.generate(data, json_path)
        shutil.copy2(json_path, os.path.join(Reporter.output_dir, "latest_report.json"))
        
        # HTML
        html_path = os.path.join(Reporter.output_dir, f"{base_filename}.html")
        html.generate(data, html_path)
        shutil.copy2(html_path, os.path.join(Reporter.output_dir, "latest_report.html"))
        
        # CSV
        csv_path = os.path.join(Reporter.output_dir, f"{base_filename}.csv")
        csv.generate(data, csv_path)
        shutil.copy2(csv_path, os.path.join(Reporter.output_dir, "latest_report.csv"))

        return {
            "json": json_path,
            "html": html_path,
            "csv": csv_path,
            "latest_html": os.path.join(Reporter.output_dir, "latest_report.html")
        }
