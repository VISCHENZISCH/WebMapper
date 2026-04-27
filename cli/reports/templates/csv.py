#!/usr/bin/env python3
# coding:utf-8
import csv

def generate(data, filepath):
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        # Header
        writer.writerow(['Vulnerability', 'Vector', 'URL/Domain', 'Parameter/Name', 'Payload/Issue'])
        
        # Vulns
        for v in data.get("vulnerabilities", []):
            writer.writerow([v.get('vuln_type'), v.get('type'), v.get('url'), v.get('param'), v.get('payload')])
            
        # Cookies
        for c in data.get("info", []):
            writer.writerow(['Cookie Security', 'INFO', c.get('domain'), c.get('name'), f"Secure:{c.get('secure')} HttpOnly:{c.get('httponly')}"])
