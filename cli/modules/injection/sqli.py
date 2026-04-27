#!/usr/bin/env python3
# coding:utf-8
import random
import urllib.parse
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from typing import List

@dataclass
class SQLIResult:
    vulnerable: bool = False
    findings: List[dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add_finding(self, type_, url, param, payload):
        self.vulnerable = True
        self.findings.append({
            "vuln_type": "Injection SQL",
            "type": type_,
            "url": url,
            "param": param,
            "payload": payload
        })

    def summary(self):
        res_str = ""
        for f in self.findings:
            res_str += f"[!] INJECTION SQL ({f['type']}) dans '{f['param']}': {f['url']}\n"
        return res_str

class SQLIModule:
    @staticmethod
    def _is_vulnerable(response_text):
        errors = [
            "You have an error in your SQL syntax;",
            "warning: mysql_fetch_array()",
            "unclosed quotation mark",
            "PostgreSQL query failed:",
            "SQLServer exception",
            "Oracle error:",
        ]
        for error in errors:
            if error.lower() in response_text.lower():
                return True
        return False

    @staticmethod
    def check_form(session, page_url, page_source):
        if page_source is None:
            return SQLIResult()
        
        result = SQLIResult()
        soup = BeautifulSoup(page_source, "html.parser")
        forms_list = soup.find_all("form")
        payload_ = "'" + random.choice("abcdefg")

        for form in forms_list:
            form_action = form.get("action") or ""
            form_method = (form.get("method") or "GET").upper()
            target_url = urllib.parse.urljoin(page_url, form_action)

            input_lists = form.find_all("input")
            params_list = {}
            for input_ in input_lists:
                input_name = input_.get("name")
                if not input_name: continue
                
                input_type = (input_.get("type") or "text").lower()
                input_value = input_.get("value") or ""

                if input_type in ["text", "password"]:
                    params_list[input_name] = payload_
                else:
                    params_list[input_name] = input_value

            try:
                if form_method == "GET":
                    res = session.get(target_url, params=params_list, timeout=10)
                else:
                    res = session.post(target_url, data=params_list, timeout=10)

                if SQLIModule._is_vulnerable(res.text):
                    result.add_finding("FORM", res.url, "Multiple/Form", payload_)
            except Exception as e:
                result.errors.append(str(e))

        return result

    @staticmethod
    def check_link(session, page_url):
        if "=" not in page_url:
            return SQLIResult()
            
        result = SQLIResult()
        parsed = urllib.parse.urlparse(page_url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        payload_ = "'" + random.choice("abcdefgehlk")

        for key in params:
            original_values = params[key]
            test_params = dict(params)
            test_params[key] = [payload_]
            
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()

            try:
                res = session.get(test_url, timeout=10)
                if SQLIModule._is_vulnerable(res.text):
                    result.add_finding("URL", res.url, key, payload_)
            except Exception as e:
                result.errors.append(str(e))
        
        return result
