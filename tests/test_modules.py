#!/usr/bin/env python3
# coding:utf-8
import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Ajout du chemin pour importer les modules du projet
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
cli_path = os.path.join(project_root, 'cli')
sys.path.append(project_root)
sys.path.append(cli_path)

from cli.modules.xss.xss import XSSModule
from cli.modules.injection.sqli import SQLIModule

class TestVulnerabilityModules(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()

    def test_xss_detection_logical(self):
        payload = "<script>alert('XSS')</script>"
        # Test réflexion directe
        self.assertTrue(XSSModule._is_vulnerable(f"<div>{payload}</div>", payload))
        # Test réflexion avec entités HTML (devrait quand même détecter si mal filtré)
        self.assertTrue(XSSModule._is_vulnerable(f"<div>&lt;script&gt;alert('XSS')&lt;/script&gt;</div>", payload))
        # Test négatif
        self.assertFalse(XSSModule._is_vulnerable("<div>Safe content</div>", payload))

    def test_sqli_detection_logical(self):
        # Test détection d'erreur MySQL
        self.assertTrue(SQLIModule._is_vulnerable("You have an error in your SQL syntax; check the manual..."))
        # Test détection d'erreur PostgreSQL
        self.assertTrue(SQLIModule._is_vulnerable("PostgreSQL query failed: ERROR: syntax error at or near \"'\""))
        # Test négatif
        self.assertFalse(SQLIModule._is_vulnerable("Welcome to your account"))

    @patch('cli.modules.xss.xss.XSSModule._is_vulnerable')
    def test_xss_check_link(self, mock_vuln):
        mock_vuln.return_value = True
        self.session.get.return_value.text = "Reflected content"
        
        url = "http://test.com/search?q=test"
        result = XSSModule.check_link(self.session, url)
        
        self.assertTrue(result.vulnerable)
        self.assertEqual(result.findings[0]['param'], 'q')

    def test_form_extraction(self):
        from bs4 import BeautifulSoup
        html = """
            <form action="/login" method="POST">
                <input name="username" type="text" value="">
                <textarea name="comment"></textarea>
                <select name="country"><option value="fr">France</option></select>
            </form>
        """
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form")
        params = XSSModule._extract_form_params(form, "PAYLOAD")
        
        self.assertEqual(params['username'], "PAYLOAD")
        self.assertEqual(params['comment'], "PAYLOAD")
        self.assertEqual(params['country'], "fr")

if __name__ == '__main__':
    unittest.main()
