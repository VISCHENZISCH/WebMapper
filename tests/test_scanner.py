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

from cli.web_scanner import WebScanner

class TestWebScanner(unittest.TestCase):
    def setUp(self):
        self.url = "http://test.com"
        self.scanner = WebScanner(self.url)

    @patch('requests.Session.get')
    def test_get_page_source(self, mock_get):
        mock_get.return_value.text = "<html><body>Test</body></html>"
        source = self.scanner.get_page_source()
        self.assertEqual(source, "<html><body>Test</body></html>")
        mock_get.assert_called_once()

    @patch('cli.web_scanner.WebScanner.get_page_source')
    def test_get_page_links(self, mock_source):
        mock_source.return_value = """
            <html>
                <body>
                    <a href="/page1">Link 1</a>
                    <a href="http://test.com/page2">Link 2</a>
                    <a href="http://external.com">External</a>
                </body>
            </html>
        """
        links = self.scanner.get_page_links()
        self.assertIn("http://test.com/page1", links)
        self.assertIn("http://test.com/page2", links)
        self.assertNotIn("http://external.com", links)

    def test_url_cleaning(self):
        scanner1 = WebScanner("http://example.com/")
        self.assertEqual(scanner1.url, "http://example.com")
        
        scanner2 = WebScanner("http://example.com")
        self.assertEqual(scanner2.url, "http://example.com")

if __name__ == '__main__':
    unittest.main()
