#!/usr/bin/env python3
# coding:utf-8
"""

WebScanner - moteur principal de WebMapper.

  - Crawling récursif du domaine cible
  - Chargement dynamique de tous les modules dans modules/
  - Exécution du scan sur chaque URL découverte
  - Agrégation des findings au format unifié

"""
import sys
import importlib
import os
import urllib.parse
import requests
from bs4 import BeautifulSoup


class WebScanner:
    def __init__(
        self,
        url: str,
        proxy: dict | None = None,
        user_agent: str = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
    ):
        self.url = url.rstrip("/")
        self.proxy = proxy
        self.user_agent = user_agent

        # Session HTTP partagée entre tous les modules
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        if self.proxy:
            self.session.proxies.update(self.proxy)

        self.stopped      = False
        self.link_list    = [self.url]   # URLs découvertes
        self.findings     = []           # Liste unifiée de findings

        # Chargement dynamique des modules
        self._modules = self._load_modules()
        print(f"\033[92m[+] {len(self._modules)} module(s) chargé(s)")

    # Chargement dynamique des modules

    def _load_modules(self) -> list:
        """
        Parcourt récursivement le dossier modules/ et charge tout fichier .py
        exposant une fonction scan(url, session) -> list[dict].
        """
        modules = []
        # Répertoire racine des modules (relatif à ce fichier)
        modules_dir = os.path.join(os.path.dirname(__file__), "modules")

        if not os.path.isdir(modules_dir):
            print("\033[91m[!] Répertoire modules/ introuvable.\033[0m")
            return modules

        for root, dirs, files in os.walk(modules_dir):
            # Ignorer les dossiers __pycache__
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for filename in sorted(files):
                if not filename.endswith(".py") or filename.startswith("_"):
                    continue
                # Construire le nom du module Python (ex: modules.headers.headers)
                rel_path = os.path.relpath(
                    os.path.join(root, filename),
                    os.path.dirname(__file__),
                )
                module_name = rel_path.replace(os.sep, ".").removesuffix(".py")
                try:
                    mod = importlib.import_module(module_name)
                    if callable(getattr(mod, "scan", None)):
                        modules.append(mod)
                    else:
                        print(f"\033[93m[!] Module {module_name} ignoré (pas de fonction scan()).\033[0m")
                except Exception as exc:
                    print(f"\033[91m[!] Erreur chargement {module_name} : {exc}\033[0m")

        return modules

    # Crawling

    def get_page_source(self, page: str | None = None) -> str | None:
        if page is None:
            page = self.url
        try:
            res = self.session.get(page, timeout=10)
            return res.text
        except Exception as exc:
            print(f"\033[91m[!] Erreur récupération {page} : {exc}\033[0m")
            return None

    def get_page_links(self, page: str | None = None) -> list[str]:
        if page is None:
            page = self.url
        link_list = []
        source = self.get_page_source(page)
        if not source:
            return []
        soup   = BeautifulSoup(source, "html.parser")
        uparse = urllib.parse.urlparse(self.url)

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if "#" in href:
                href = href.split("#")[0]
            new_link = urllib.parse.urljoin(page, href)
            if uparse.hostname not in new_link:
                continue
            clean = new_link.rstrip("/")
            if clean not in [l.rstrip("/") for l in self.link_list]:
                link_list.append(new_link)

        return link_list

    def crawl(self, page: str | None = None):
        """Crawling récursif du domaine cible."""
        if page is None:
            page = self.url
        try:
            for link in self.get_page_links(page):
                if self.stopped:
                    break
                if link not in self.link_list:
                    self.link_list.append(link)
                    print(f"\033[94m[+] Lien :\033[0m \033[96m{link}\033[0m")
                    self.crawl(link)
        except KeyboardInterrupt:
            print("\n\033[93m[!] Crawl interrompu.\033[0m")
            sys.exit(0)

    
    # Scan de vulnérabilités
   
    def _run_modules_on(self, url: str):
        """Exécute tous les modules chargés sur une URL et agrège les findings."""
        for mod in self._modules:
            if self.stopped:
                break
            mod_name = mod.__name__.split(".")[-1]
            try:
                results = mod.scan(url, self.session)
                if results:
                    self.findings.extend(results)
                    for f in results:
                        sev   = f.get("severity", "info").upper()
                        ftype = f.get("type", "?")
                        color = {
                            "CRITICAL": "\033[91m",
                            "HIGH":     "\033[91m",
                            "MEDIUM":   "\033[93m",
                            "LOW":      "\033[96m",
                            "INFO":     "\033[97m",
                        }.get(sev, "\033[97m")
                        print(f"  {color}[{sev}] {ftype}\033[0m — {f.get('detail','')[:120]}")
            except Exception as exc:
                print(f"\033[91m  [!] Erreur dans le module {mod_name} : {exc}\033[0m")

    def run_full_scan(self):
        """Crawl + scan de vulnérabilités sur toutes les URLs découvertes."""
        print(f"\n\033[94m[*] Début du scan complet sur : \033[96m{self.url}\033[0m")
        self.crawl()
        print(f"\n\033[94m[*] {len(self.link_list)} URL(s) à analyser.\033[0m\n")
        self._scan_link_list()

    def run_vuln_scan(self):
        """Scan de vulnérabilités uniquement sur l'URL cible (sans crawl)."""
        print(f"\n\033[94m[*] Analyse directe sur : \033[96m{self.url}\033[0m")
        self.link_list = [self.url]
        self._scan_link_list()

    def _scan_link_list(self):
        """Exécute les modules sur toutes les URLs dans link_list."""
        _header = "+" + " - " * 25
        print("\n\033[94m" + _header)
        print("\t\t\t[*] Lancement de la recherche de vulnérabilités...")
        print(_header + "\033[0m\n")

        for i, link in enumerate(self.link_list, 1):
            if self.stopped:
                break
            print(f"\033[94m[{i}/{len(self.link_list)}] Analyse :\033[0m \033[96m{link}\033[0m")
            try:
                self._run_modules_on(link)
            except KeyboardInterrupt:
                print("\n\033[93m[!] Scan interrompu.\033[0m")
                self.stopped = True
                break
            print()