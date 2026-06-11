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
import shlex
import urllib.parse
import requests
import warnings
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import random
from utils import USER_AGENTS
from utils.session_manager import SessionManager
from utils.processor import ResultAggregator
from modules.recon.subdomain_enum import SubdomainEnumerator
from modules.recon.port_scanner import PortScanner
from modules.recon.nuclei_runner import NucleiRunner

# Constantes de couleurs premium ANSI
RESET      = "\033[0m"
BOLD       = "\033[1m"
DIM        = "\033[2m"
SKY_BLUE   = "\033[38;5;39m"
EMERALD    = "\033[38;5;46m"
GOLD       = "\033[38;5;220m"
CRIMSON    = "\033[38;5;196m"
PURPLE     = "\033[38;5;141m"
MAGENTA    = "\033[38;5;201m"
DARK_GREY  = "\033[38;5;243m"
WHITE      = "\033[97m"

def _format_exc(exc: Exception) -> str:
    msg = str(exc)
    if "Network is unreachable" in msg:
        return "Hôte inatteignable (Pare-feu ou réseau coupé)"
    if "Name or service not known" in msg:
        return "Résolution DNS impossible"
    if "Connection refused" in msg:
        return "Connexion refusée"
    if "timed out" in msg.lower() or "timeout" in msg.lower():
        return "Délai d'attente dépassé (Timeout)"
    return msg



class WebScanner:
    def __init__(
        self,
        url: str,
        proxy: dict | None = None,
        user_agent: str = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        max_threads: int = 5,
        rotate_ua: bool = True,
        wordlist: str | None = None,
        ports_config: str | None = None,
        nuclei_args: str | None = None,
    ):
        self.url = url.rstrip("/")
        self.proxy = proxy
        self.user_agent = user_agent
        self.max_threads = max_threads
        self.rotate_ua = rotate_ua
        self.wordlist = wordlist
        self.ports_config = ports_config
        self.nuclei_args = nuclei_args

        # Gestionnaire de sessions HTTP isolées (fix bugs #2 & #3)
        # Chaque module/thread reçoit sa propre session avec son
        # propre pool de connexions, cookies et headers.
        self.session_manager = SessionManager(
            proxy=proxy,
            rotate_ua=rotate_ua,
            user_agent=user_agent,
        )

        # Session principale pour le crawl (isolée des modules)
        self.session = self.session_manager.create_session()

        self.stopped      = False
        self.link_list    = [self.url]   # URLs découvertes
        self.aggregator   = ResultAggregator()  # Format unifié (fix bug #7)

        # Locks pour la thread-safety
        self.print_lock   = threading.Lock()
        self.findings_lock = threading.Lock()

        # Chargement dynamique des modules
        self._modules = self._load_modules()
        print(f"{EMERALD}[+] {len(self._modules)} module(s) chargé(s){RESET}")

    @property
    def findings(self) -> list[dict]:
        """Retourne la liste des findings au format dict (rétrocompatibilité)."""
        return self.aggregator.finalize().to_dict_list()

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
            print(f"{CRIMSON}[!] Répertoire modules/ introuvable.{RESET}")
            return modules

        for root, dirs, files in os.walk(modules_dir):
            # Ignorer les dossiers __pycache__ et recon (les modules de recon ne s'exécutent pas par URL)
            dirs[:] = [d for d in dirs if d not in ("__pycache__", "recon")]
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
                        print(f"{GOLD}[!] Module {module_name} ignoré (pas de fonction scan()).{RESET}")
                except Exception as exc:
                    print(f"{CRIMSON}[!] Erreur chargement {module_name} : {exc}{RESET}")

        return modules

    # Crawling

    def get_page_source(self, page: str | None = None) -> str | None:
        if page is None:
            page = self.url
        try:
            res = self.session.get(page, timeout=10)
            return res.text
        except Exception as exc:
            msg = str(exc)
            if "Network is unreachable" in msg:
                msg = "Hôte inatteignable (Pare-feu ou réseau coupé)"
            elif "Name or service not known" in msg:
                msg = "Résolution DNS impossible"
            elif "Connection refused" in msg:
                msg = "Connexion refusée"
            elif "timed out" in msg.lower() or "timeout" in msg.lower():
                msg = "Délai d'attente dépassé (Timeout)"
            print(f"{CRIMSON}[!] Erreur récupération {page} : {msg}{RESET}")
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
                        print(f"{SKY_BLUE}[+] {RESET}Lien découvert : {WHITE}{link}{RESET}")
        except KeyboardInterrupt:
            print(f"\n{GOLD}[!] Crawl interrompu.{RESET}")
            sys.exit(0)

    
    # Scan de vulnérabilités
   
    def _run_modules_on(self, url: str):
        """Exécute tous les modules chargés sur une URL et agrège les findings."""
        # Session isolée par thread via SessionManager (fix bugs #2 & #3)
        session = self.session_manager.get_thread_session()

        for mod in self._modules:
            if self.stopped:
                break
            mod_name = mod.__name__.split(".")[-1]
            try:
                # Rotation de User-Agent par URL (la session est isolée par thread)
                ua = random.choice(USER_AGENTS) if self.rotate_ua else self.user_agent
                session.headers.update({
                    "User-Agent": ua,
                    "Referer": url,
                })

                results = mod.scan(url, session)
                if results:
                    with self.findings_lock:
                        self.aggregator.add_findings(results, source=mod_name)
                    with self.print_lock:
                        for f in results:
                            sev   = f.get("severity", "info").upper()
                            ftype = f.get("type", "?")
                            
                            color, label = {
                                "CRITICAL": (CRIMSON, "[CRITICAL]"),
                                "HIGH":     (CRIMSON, "[HIGH]    "),
                                "MEDIUM":   (GOLD,    "[MEDIUM]  "),
                                "LOW":      (SKY_BLUE, "[LOW]     "),
                                "INFO":     (WHITE,    "[INFO]    "),
                            }.get(sev, (WHITE, "[INFO]    "))
                            
                            detail = f.get('detail', '')
                            if len(detail) > 95:
                                detail = detail[:92] + "..."
                            print(f"{color}{label} {ftype:<30} {RESET}- {detail}")
            except Exception as exc:
                with self.print_lock:
                    print(f"{CRIMSON}[!] Erreur module {mod_name} sur {url} : {_format_exc(exc)}{RESET}")

    def _run_dns_enum(self):
        """Exécute l'énumération de sous-domaines."""
        domain = urllib.parse.urlparse(self.url).hostname
        if not domain: return []
        
        print(f"\n{BOLD}{SKY_BLUE}[*] Énumération des sous-domaines pour {WHITE}{domain}{RESET}\n")
        enum = SubdomainEnumerator(domain=domain, workers=self.max_threads, wordlist=self.wordlist)
        self.subdomains = enum.enumerate()
        return self.subdomains

    def _run_port_scan(self, targets: list | None = None, deep_scan: bool = False):
        """Lance l'énumération des ports ouverts."""
        if targets is None:
            targets = getattr(self, "subdomains", [])

        if not targets:
            domain = urllib.parse.urlparse(self.url).hostname
            if not domain: return
            targets = [domain]
            
        ports_tuple = None
        if self.ports_config and self.ports_config.lower() != "top100":
            try:
                ports_tuple = tuple(int(p.strip()) for p in self.ports_config.split(",") if p.strip())
            except ValueError:
                with self.print_lock:
                    print(f"{CRIMSON}[!] Argument ports invalide ({self.ports_config}), fallback sur top100.{RESET}")

        # Déduplication par adresse IP pour éviter de scanner la même machine N fois
        ip_to_subs = {}
        for target in targets:
            ip = target.ip if hasattr(target, 'ip') else target
            sub = target.subdomain if hasattr(target, 'subdomain') else target
            
            if ip not in ip_to_subs:
                ip_to_subs[ip] = []
            ip_to_subs[ip].append(sub)

        unique_ips = list(ip_to_subs.keys())
        print(f"\n{BOLD}{SKY_BLUE}[*] Scan de ports sur {len(unique_ips)} IP(s) unique(s) ({len(targets)} sous-domaines){RESET}\n")
        
        nmap_profile = "deep" if deep_scan else "default"
        
        for ip in unique_ips:
            ps = PortScanner(target=ip, ports=ports_tuple, workers=self.max_threads, nmap_profile=nmap_profile)
            ports = ps.scan()
            if not ports:
                print(f"  {DARK_GREY}[i] Aucun port ouvert trouvé sur {ip}{RESET}")
            else:
                if ps.os_match:
                    print(f"\n  {MAGENTA}[*] OS Détecté sur {ip} : {WHITE}{ps.os_match}{RESET}")
                
                for p in ports:
                    print(f"  {EMERALD}[+] {RESET}Port ouvert sur {WHITE}{ip}{RESET} : {EMERALD}{p.port}/tcp{RESET} ({p.service} {p.version})")
                    if p.banner:
                        # Affichage du contenu des scripts Nmap / Bannières dans la console
                        chunks = [c.strip() for c in p.banner.split(" | ") if c.strip()]
                        for chunk in chunks:
                            is_vuln = any(kw in chunk.upper() for kw in ["VULNERABLE", "CVE-", "EXPLOIT", "ERROR"])
                            color = CRIMSON if is_vuln else DARK_GREY
                            # Nettoyer les sauts de ligne pour un affichage compact
                            display_chunk = chunk.replace('\n', ' ')
                            if len(display_chunk) > 1000:
                                display_chunk = display_chunk[:997] + "..."
                            
                            import textwrap
                            # On coupe intelligemment avec une indentation pour les lignes suivantes
                            wrapped = textwrap.fill(display_chunk, width=100, subsequent_indent="          ")
                            print(f"      {color}↳ {wrapped}{RESET}")
                    # Ajouter un finding pour chaque sous-domaine partageant cette IP
                    for sub in ip_to_subs[ip]:
                        self.aggregator.add_findings([{
                            "type": "OPEN_PORT",
                            "severity": "info",
                            "url": f"http://{sub}:{p.port}",
                            "detail": f"Port {p.port} ouvert sur {sub} ({p.service} {p.version})",
                            "evidence": p.banner
                        }], source="port_scanner")

    def _run_nuclei(self):
        """Lance Nuclei sur toutes les URLs découvertes."""
        if not NucleiRunner.is_available():
            print(f"\n{GOLD}[i] Nuclei non installé, étape ignorée.{RESET}")
            return
            
        extra_args = []
        if self.nuclei_args:
            extra_args = shlex.split(self.nuclei_args)
            
        print(f"\n{BOLD}{SKY_BLUE}[*] Lancement de Nuclei sur {len(self.link_list)} URL(s){RESET}")
        runner = NucleiRunner(urls=self.link_list, extra_args=extra_args)
        nuclei_findings = runner.run()
        if nuclei_findings:
            with self.findings_lock:
                self.aggregator.add_findings(nuclei_findings, source="nuclei")
            print(f"{EMERALD}[+] {len(nuclei_findings)} finding(s) Nuclei ajouté(s).{RESET}")

    def run_full_scan(self):
        """Scan complet (Recon -> Crawl -> Modules -> Nuclei)."""
        print(f"\n{BOLD}{SKY_BLUE}[*] Début du scan complet sur : {WHITE}{self.url}{RESET}")
        
        # 1. Reconnaissance DNS / Ports (Feature #5 et #5bis)
        subs = self._run_dns_enum()
        if subs:
            self._run_port_scan(subs)
        else:
            self._run_port_scan()
        
        # 2. Crawl
        self.crawl()
        print(f"\n{BOLD}{SKY_BLUE}[*] {len(self.link_list)} URL(s) à analyser.{RESET}\n")
        
        # 3. Scan vulnérabilités via modules
        self._scan_link_list()
        
        # 4. Nuclei (Feature #6)
        self._run_nuclei()

    def run_vuln_scan(self):
        """Scan de vulnérabilités uniquement sur l'URL cible (sans crawl)."""
        print(f"\n{BOLD}{SKY_BLUE}[*] Analyse directe sur : {WHITE}{self.url}{RESET}")
        self.link_list = [self.url]
        self._scan_link_list()

    def run_dns_only(self):
        """Exécute uniquement la phase de reconnaissance DNS."""
        print(f"\n{BOLD}{SKY_BLUE}[*] Début de la reconnaissance DNS sur : {WHITE}{self.url}{RESET}")
        self._run_dns_enum()

    def run_ports_only(self):
        """Exécute uniquement le scan de ports sur la cible."""
        print(f"\n{BOLD}{SKY_BLUE}[*] Début du scan de ports sur : {WHITE}{self.url}{RESET}")
        self._run_port_scan(deep_scan=True)

    def run_nuclei_only(self):
        """Exécute uniquement Nuclei sur l'URL cible (sans crawl)."""
        print(f"\n{BOLD}{SKY_BLUE}[*] Début du scan Nuclei sur : {WHITE}{self.url}{RESET}")
        self.link_list = [self.url]
        self._run_nuclei()

    def _scan_link_list(self):
        """Exécute les modules sur toutes les URLs dans link_list en parallèle."""
        with self.print_lock:
            print(f"[*] {'Lancement de la recherche de vulnérabilités...'.center(50)}\n")
         

        total_urls = len(self.link_list)
        completed_count = 0
        counter_lock = threading.Lock()

        def worker(link):
            nonlocal completed_count
            if self.stopped:
                return
                
            # OPSEC: Jitter (délai aléatoire) pour éviter les signatures de vélocité
            time.sleep(random.uniform(0.5, 2.5))
            
            with self.print_lock:
                print(f"{SKY_BLUE}[*]{RESET} Analyse de : {BOLD}{WHITE}{link}{RESET}\n")
            
            try:
                self._run_modules_on(link)
            except Exception as exc:
                with self.print_lock:
                    print(f"{CRIMSON}[!] Erreur traitement {link} : {_format_exc(exc)}{RESET}")

            with counter_lock:
                completed_count += 1
                current = completed_count
            with self.print_lock:
                print(f"\n{EMERALD}[+] [{current}/{total_urls}]{RESET} Terminé : {DARK_GREY}{link}{RESET}\n")

        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(worker, link) for link in self.link_list]
                for future in futures:
                    future.result()
        except KeyboardInterrupt:
            with self.print_lock:
                print(f"\n{GOLD}[!] Scan interrompu.{RESET}")
            self.stopped = True