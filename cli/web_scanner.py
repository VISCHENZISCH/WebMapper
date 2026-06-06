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
import threading
from concurrent.futures import ThreadPoolExecutor


import random
from utils import USER_AGENTS


class WebScanner:
    def __init__(
        self,
        url: str,
        proxy: dict | None = None,
        user_agent: str = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        max_threads: int = 5,
        rotate_ua: bool = True,
    ):
        self.url = url.rstrip("/")
        self.proxy = proxy
        self.user_agent = user_agent
        self.max_threads = max_threads
        self.rotate_ua = rotate_ua

        # Session HTTP partagée entre tous les modules
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        if self.proxy:
            self.session.proxies.update(self.proxy)

        self.stopped      = False
        self.link_list    = [self.url]   # URLs découvertes
        self.findings     = []           # Liste unifiée de findings
        
        # Locks pour la thread-safety
        self.print_lock   = threading.Lock()
        self.findings_lock = threading.Lock()

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
        seen_clean = set()  # O(1) lookup au lieu de O(n) list scan
        source = self.get_page_source(page)
        if not source:
            return []
        soup   = BeautifulSoup(source, "html.parser")
        uparse = urllib.parse.urlparse(self.url)

        def _try_add(raw_link: str):
            """Ajoute un lien s'il est dans le scope et non dupliqué."""
            new_parse = urllib.parse.urlparse(raw_link)
            if not new_parse.hostname or uparse.hostname not in new_parse.hostname:
                return
            clean = raw_link.rstrip("/")
            if clean not in seen_clean:
                seen_clean.add(clean)
                link_list.append(raw_link)

        # 1. Extraction des liens hypertexte <a>
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].split("#")[0]
            _try_add(urllib.parse.urljoin(page, href))

        # 2. Extraction des cibles de formulaires
        for form in soup.find_all("form", action=True):
            action = form["action"].split("#")[0]
            _try_add(urllib.parse.urljoin(page, action))

        return link_list

    def crawl(self, max_pages: int = 100):
        """Crawling itératif (BFS) du domaine cible pour éviter RecursionError."""
        from collections import deque

        queue = deque([self.url])
        visited = {self.url.rstrip("/")}
        self.link_list = [self.url]

        pages_count = 0
        try:
            while queue and pages_count < max_pages:
                if self.stopped:
                    break
                current_url = queue.popleft()
                pages_count += 1

                # Extraction des liens
                links = self.get_page_links(current_url)
                for link in links:
                    clean = link.rstrip("/")
                    if clean not in visited:
                        visited.add(clean)
                        self.link_list.append(link)
                        queue.append(link)
                        print(f"\033[94m[+] Lien :\033[0m \033[96m{link}\033[0m")
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
                # Chaque thread utilise sa propre session pour éviter les conflits d'état de requêtes simultanées
                # mais hérite de la configuration globale.
                thread_session = requests.Session()
                
                # Rotation de User-Agent et en-têtes réalistes pour éviter les détections WAF simples
                ua = random.choice(USER_AGENTS) if self.rotate_ua else self.user_agent
                thread_session.headers.update({
                    "User-Agent": ua,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
                    "Referer": url,
                })
                
                if self.proxy:
                    thread_session.proxies.update(self.proxy)



                results = mod.scan(url, thread_session)
                if results:
                    with self.findings_lock:
                        self.findings.extend(results)
                    with self.print_lock:
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
                with self.print_lock:
                    print(f"\033[91m  [!] Erreur dans le module {mod_name} sur {url} : {exc}\033[0m")

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
        """Exécute les modules sur toutes les URLs dans link_list en parallèle."""
        _header = "+" + " - " * 25
        print("\n\033[94m" + _header)
        print("\t\t\t[*] Lancement de la recherche de vulnérabilités...")
        print(_header + "\033[0m\n")

        total_urls = len(self.link_list)
        completed_count = 0
        counter_lock = threading.Lock()

        def worker(link):
            nonlocal completed_count
            if self.stopped:
                return
            with self.print_lock:
                print(f"\033[94m[*] Analyse de :\033[0m \033[96m{link}\033[0m")
            
            try:
                self._run_modules_on(link)
            except Exception as exc:
                with self.print_lock:
                    print(f"\033[91m[!] Erreur lors du traitement de {link} : {exc}\033[0m")

            with counter_lock:
                completed_count += 1
                current = completed_count
            with self.print_lock:
                print(f"\033[92m[+] [{current}/{total_urls}]\033[0m Terminé : \033[96m{link}\033[0m\n")

        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(worker, link) for link in self.link_list]
                for future in futures:
                    future.result()
        except KeyboardInterrupt:
            with self.print_lock:
                print("\n\033[93m[!] Scan interrompu.\033[0m")
            self.stopped = True