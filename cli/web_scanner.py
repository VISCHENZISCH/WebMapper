#!/usr/bin/env python3
# coding:utf-8
import sys
import urllib.parse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Importation des modules de vulnérabilités
from modules.injection.sqli import SQLIModule
from modules.xss.xss import XSSModule
from modules.info.cookies import CookieModule

class WebScanner:
    def __init__(self, url, proxy=None, user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"):
        if url.endswith("/"):
            self.url = url.rstrip("/")
        else:
            self.url = url
        self.proxy = proxy
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers.update({"User-agent": self.user_agent})
        if self.proxy:
            self.session.proxies.update(self.proxy)
            
        self.stopped = False
        self.link_list = [self.url]
        self.results_list = [] # Stockage des résultats pour le reporter

    def get_page_source(self, page=None):
        if page is None:
            page = self.url
        try:
            res = self.session.get(page, timeout=10)
            return res.text
        except Exception as e:
            print(f"[!] Erreur lors de la récupération de {page} : {e}")
            return None

    def get_page_links(self, page=None):
        link_list = []
        if page is None:
            page = self.url
        
        source = self.get_page_source(page)
        if source:
            soup = BeautifulSoup(source, "html.parser")
            uparse = urlparse(self.url)
            for link in soup.find_all('a'):
                href = link.get("href")
                if href:
                    if '#' in href:
                        href = href.split('#')[0]
                    new_link = urllib.parse.urljoin(page, href)
                    if uparse.hostname in new_link and new_link not in self.link_list:
                        # On évite de rajouter des doublons qui ne diffèrent que par le slash de fin
                        clean_link = new_link.rstrip('/')
                        if clean_link not in [l.rstrip('/') for l in self.link_list]:
                            link_list.append(new_link)
            return link_list
        return []

    def crawl(self, page=None):
        if page is None:
            page = self.url
        
        try:
            links_to_crawl = self.get_page_links(page)
            for link in links_to_crawl:
                if self.stopped:
                    break
                if link not in self.link_list:
                    self.link_list.append(link)
                    print(f"\033[94m[+] Lien découvert :\033[0m \033[96m{link}\033[0m")
                    self.crawl(link)
        except KeyboardInterrupt:
            print(f"\n\033[94m[!] Scan interrompu.\033[0m")
            sys.exit(0)

    def check_cookies(self):
        """
        Effectue une analyse de sécurité des cookies
        """
        print("\033[94m[+] Collecte d'informations (Cookies)...\033[0m")
        try:
            # On tente de récupérer la réponse brute pour une analyse précise des headers (HttpOnly/SameSite)
            root_res = self.session.get(self.url, timeout=10)
            res_cookies = CookieModule.analyze(self.session, response=root_res)
        except Exception:
            # Fallback sur l'analyse de session uniquement si la requête échoue
            res_cookies = CookieModule.analyze(self.session)
            
        self.results_list.append(res_cookies)
        print(res_cookies.summary())

    def check_vulnerabilities(self):
        """
        Lance la recherche de vulnérabilités sur tous les liens découverts
        """
        print("\n\033[94m" + "+ - "*25)
        print("\t\t\t[*] Lancement de la recherche de vulnérabilités...")
        print("+ - "*25 + "\033[0m\n")

        # --- COLLECTE D'INFORMATIONS ---
        self.check_cookies()
        print("+ - " * 25 + "\n")

        for link in self.link_list:
            if self.stopped:
                break
            
            print(f"\033[94m[*] Analyse de :\033[0m \033[96m{link}\033[0m")
            
            # Récupération de la source une seule fois pour les tests de formulaires
            source = self.get_page_source(link)
            
            # SQL INJECTION
            # Test dans les formulaires
            res_sqli_form = SQLIModule.check_form(self.session, link, source)
            if res_sqli_form.vulnerable:
                self.results_list.append(res_sqli_form)
                print(f"\033[91m{res_sqli_form.summary()}\033[0m", end="") # Affichage en rouge
            
            # Test dans l'URL
            res_sqli_link = SQLIModule.check_link(self.session, link)
            if res_sqli_link.vulnerable:
                self.results_list.append(res_sqli_link)
                print(f"\033[91m{res_sqli_link.summary()}\033[0m", end="")

            # XSS
            # Test dans les formulaires
            res_xss_form = XSSModule.check_form(self.session, link, source)
            if res_xss_form.vulnerable:
                self.results_list.append(res_xss_form)
                print(f"\033[93m{res_xss_form.summary()}\033[0m", end="") # Affichage en jaune/ambre
            
            # Test dans l'URL
            res_xss_link = XSSModule.check_link(self.session, link)
            if res_xss_link.vulnerable:
                self.results_list.append(res_xss_link)
                print(f"\033[93m{res_xss_link.summary()}\033[0m", end="")
            
            print() # Saut de ligne entre chaque analyse
            
            print() # Saut de ligne entre chaque analyse