#!/usr/bin/env python3
# coding:utf-8
import json

class ResultFormatter:
    @staticmethod
    def to_generic_dict(results_list):
        """
        Convertit une liste de dataclasses (XSSResult, SQLIResult, CookieResult)
        en un dictionnaire générique pour les exports.
        """
        formatted = {
            "vulnerabilities": [],
            "info": []
        }
        
        for res in results_list:
            if hasattr(res, 'findings'): # Vulnérabilités
                for finding in res.findings:
                    formatted["vulnerabilities"].append(finding)
            if hasattr(res, 'cookies'): # Cookies
                for cookie in res.cookies:
                    # On utilise la méthode masked_value si dispo, ou on serialise
                    formatted["info"].append({
                        "type": "cookie",
                        "name": cookie.name,
                        "domain": cookie.domain,
                        "secure": cookie.secure,
                        "httponly": cookie.httponly
                    })
        return formatted
