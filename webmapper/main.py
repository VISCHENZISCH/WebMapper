#!/usr/bin/env python3
# coding:utf-8
"""
WebMapper CLI
"""
import sys
import os
import logging
import argparse
import web_scanner
from reports.reporter import Reporter
from utils import MarginStdout
from utils.url_validator import validate_url

# Constantes de couleurs ANSI 256 / 24-bit TrueColor
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
ITALIC  = "\033[3m"
UNDERLINE = "\033[4m"

# Couleurs personnalisées
CRIMSON  = "\033[38;5;196m"
EMERALD  = "\033[38;5;46m"
GOLD     = "\033[38;5;220m"
SKY_BLUE = "\033[38;5;39m"
PURPLE   = "\033[38;5;141m"
MAGENTA  = "\033[38;5;201m"
DARK_GREY = "\033[38;5;243m"
WHITE    = "\033[37m"

# Couleurs classiques (mappées sur la palette premium)
RED    = CRIMSON
GREEN  = EMERALD
YELLOW = GOLD
BLUE   = SKY_BLUE
CYAN   = SKY_BLUE
WHITE  = "\033[97m"
DIM    = "\033[2m"

def c(color: str, text: str = "", bold: bool = False) -> str:
    """Applique une couleur ANSI à un texte."""
    return f"{BOLD if bold else ''}{color}{text}{RESET if text else ''}"


def show_banner() -> None:
    banner = f"""
{c(SKY_BLUE, bold=True)}  {c(MAGENTA, " __      __      ___. _____", bold=True)}                                           {c(SKY_BLUE, bold=True)}
{c(SKY_BLUE, bold=True)}  {c(MAGENTA, " \\ \\    /  \\ ____\\_ |__/     \\ _____  ______ ______   ___________  ", bold=True)} {c(SKY_BLUE, bold=True)}
{c(SKY_BLUE, bold=True)}  {c(PURPLE, "  \\ \\/\\/   // __ \\| __ \\  \\ /  \\\\__  \\ \\____ \\\\____ \\_/ __ \\_  __ \\", bold=True)} {c(SKY_BLUE, bold=True)}
{c(SKY_BLUE, bold=True)}  {c(PURPLE, "   \\        /\\  ___/| \\_\\ \\   Y  / / __ \\|  |_> >  |_> >\\  ___/|  | \\/", bold=True)}  {c(SKY_BLUE, bold=True)}
{c(SKY_BLUE, bold=True)}  {c(SKY_BLUE, "    \\__/\\  /  \\___  >___  /__|_|  /(____  /   __/|   __/  \\___  >__|   ", bold=True)}  {c(SKY_BLUE, bold=True)}
{c(SKY_BLUE, bold=True)}  {c(SKY_BLUE, "         \\/       \\/    \\/      \\/      \\/|__|   |__|         \\/       ", bold=True)}  {c(SKY_BLUE, bold=True)}
"""
    print(banner)
    print("\t\t\t\t" + c(YELLOW, '© 2026 Félix TOVIGNAN'))
    print("\t\t" + c(GREEN, 'https://github.com/VISCHENZISCH/WebMapper.git\n'))

    # Usage & options
    print(f"  {c(WHITE, 'usage:', bold=True)} {c(DARK_GREY, './webmapper.sh')} {c(SKY_BLUE, '[-h] [-t THREADS] [--proxy PROXY] [--no-rotate-ua] [-v] [--wordlist FILE] [--ports PORTS] [--nuclei-args ARGS]')} {c(GOLD, '[url]')}")
    print()
    print(f"  {c(WHITE, 'arguments :', bold=True)}")
    print(f"    {c(GOLD, 'url')}                 URL cible {c(DARK_GREY, '(ex: http://example.com)')}")
    print()
    print(f"  {c(WHITE, 'options globales :', bold=True)}")
    print(f"    {c(SKY_BLUE, '-t, --threads N')}    Threads parallèles  {c(DARK_GREY, '(défaut: 5)')}")
    print(f"    {c(SKY_BLUE, '--proxy URL')}        Proxy HTTP          {c(DARK_GREY, '(ex: http://127.0.0.1:8080)')}")
    print(f"    {c(SKY_BLUE, '--no-rotate-ua')}     Désactiver la rotation de User-Agent")
    print(f"    {c(SKY_BLUE, '-v, --verbose')}      Mode verbose")
    print(f"    {c(SKY_BLUE, '--wordlist FILE')}    Wordlist pour l'énumération DNS")
    print(f"    {c(SKY_BLUE, '--ports PORTS')}      Ports à scanner {c(DARK_GREY, '(ex: 80,443,8080 ou top100)')}")
    print(f"    {c(SKY_BLUE, '--nuclei-args')}      Arguments additionnels pour Nuclei {c(DARK_GREY, '(ex: \"-tags cve\")')}")
    print()
    print(f"  {c(WHITE, 'exemple :', bold=True)}")
    print(f"    {c(DARK_GREY, '$')} {c(EMERALD, './webmapper.sh')} {c(GOLD, 'http://target.com')} {c(SKY_BLUE, '-t 10 --proxy http://127.0.0.1:8080 -v')}")


def clear_terminal() -> None:
    print("\033c", end="")


def ask_to_continue() -> bool:
    print("\n" + c(BLUE, "+ - ") * 25)
    prompt = c(BLUE, "[?]") + " " + c(WHITE, "Continuer à utiliser WebMapper ? (o/n) : ")
    choice = input(prompt).strip().lower()
    if choice == "o":
        clear_terminal()
        show_banner()
        return True
    print("\n" + c(GREEN, "[*] Merci d'avoir utilisé WebMapper. À bientôt !"))
    return False


def print_report_paths(paths: dict) -> None:
    print(f"\n{c(BLUE, '[+] Rapports générés :')}\n")
    print(f"\t   {c(GREEN, '-')} {c(WHITE, 'HTML')}  : {c(CYAN, paths.get('html', '-'))}")
    print(f"\t   {c(GREEN, '-')} {c(WHITE, 'JSON')}  : {c(CYAN, paths.get('json', '-'))}")
    print(f"\t   {c(GREEN, '-')} {c(WHITE, 'CSV')}   : {c(CYAN, paths.get('csv',  '-'))}")
    print(f"\t   {c(GREEN, '-')} {c(WHITE, 'SARIF')} : {c(CYAN, paths.get('sarif', '-'))}")


def print_config(args) -> None:
    """Affiche la configuration active du scanner."""
    print(f"\n{c(BLUE, '[*] Configuration :')}")
    print(f"    {c(WHITE, 'Cible')}        : {c(CYAN, args.url)}")
    print(f"    {c(WHITE, 'Threads')}      : {c(CYAN, str(args.threads))}")
    print(f"    {c(WHITE, 'Rotation UA')}  : {c(CYAN, 'Oui' if not args.no_rotate_ua else 'Non')}")
    if args.proxy:
        print(f"    {c(WHITE, 'Proxy')}        : {c(CYAN, args.proxy)}")
    if args.verbose:
        print(f"    {c(WHITE, 'Mode')}         : {c(YELLOW, 'VERBOSE')}")
    if getattr(args, "wordlist", None):
        print(f"    {c(WHITE, 'Wordlist')}     : {c(CYAN, args.wordlist)}")
    if getattr(args, "ports", None):
        print(f"    {c(WHITE, 'Ports')}        : {c(CYAN, args.ports)}")
    if getattr(args, "nuclei_args", None):
        print(f"    {c(WHITE, 'Nuclei Args')}  : {c(CYAN, args.nuclei_args)}")


# Menu 

def print_menu() -> None:
    items = [
        ("1", "Scan Complet",       "FULL", "Recon + Crawl + Modules + Nuclei"),
        ("2", "Scan Direct",        "FAST", "Vulnérabilités sur l'URL cible uniquement"),
        ("3", "Crawler uniquement", "MAP",  "Découverte de liens"),
        ("4", "Énumération DNS",    "DNS",  "Découverte de sous-domaines"),
        ("5", "Scan de ports",      "PORT", "Recherche de services ouverts"),
        ("6", "Scan Nuclei",        "CVE",  "Exécution de Nuclei sur l'URL cible"),
        ("7", "Quitter",            "",     ""),
    ]
    print(f"\n{c(YELLOW, '║ Utilisation réservée aux tests autorisés uniquement.')}\n")
    sep = c(RED, "══════════════", bold=True)
    print(f"{c(BLUE, '[ ✔✘!?→ ]')} {sep} {c(GREEN, 'MENU DE SCAN', bold=True)} {sep} {c(BLUE, '[ ✔✘!?→ ]')}\n")
    for num, label, badge, desc in items:
        badge_str = f" {c(CYAN, f'[{badge}]')}" if badge else ""
        desc_str  = f"  {c(DIM + WHITE, desc)}" if desc else ""
        print(f"  {c(BLUE, num, bold=True)}.  {c(WHITE, label, bold=True)}{badge_str}{desc_str}")


# Dispatcher

ACTIONS = {
    "1": ("run_full_scan",  "full_scan",   "Scan complet"),
    "2": ("run_vuln_scan",  "direct_scan", "Analyse directe"),
    "3": ("crawl",          "crawl_only",  "Crawling"),
    "4": ("run_dns_only",   "dns_enum",    "Énumération DNS"),
    "5": ("run_ports_only", "port_scan",   "Scan de ports"),
    "6": ("run_nuclei_only","nuclei",      "Scan Nuclei"),
}


def run_action(ws, action_key: str) -> int:
    """
    Exécute un scan et retourne un code de sortie CI/CD.
    0 = aucun finding critique/high, 1 = au moins un finding critique/high.
    """
    method_name, report_key, label = ACTIONS[action_key]
    try:
        getattr(ws, method_name)()
        print(f"\n{c(GREEN, f'[*] {label} terminé.')}")
    except KeyboardInterrupt:
        print(f"\n{c(YELLOW, '[!] Scan interrompu.')}")

    # Injection des données passives (DNS, Crawl) dans l'agrégateur pour qu'elles figurent dans tous les rapports HTML/CSV
    if hasattr(ws, 'subdomains') and ws.subdomains:
        dns_findings = []
        for sub in ws.subdomains:
            dns_findings.append({
                "type": "DNS_SUBDOMAIN",
                "severity": "info",
                "url": f"http://{sub.subdomain}",
                "detail": f"Sous-domaine {sub.subdomain} résolu vers {sub.ip}",
                "evidence": "dns_enum"
            })
        ws.aggregator.add_findings(dns_findings, source="dns")
        
    if hasattr(ws, 'link_list') and len(ws.link_list) > 1:
        crawl_findings = []
        for link in ws.link_list:
            if link.rstrip("/") != ws.url.rstrip("/"):
                crawl_findings.append({
                    "type": "CRAWLED_ENDPOINT",
                    "severity": "info",
                    "url": link,
                    "detail": "URL découverte lors du crawling",
                    "evidence": "crawler"
                })
        ws.aggregator.add_findings(crawl_findings, source="crawler")

    if ws.findings:
        paths = Reporter.generate_all(ws.findings, report_key)
        print_report_paths(paths)

        # Code de sortie CI/CD : 1 si au moins un finding critical ou high
        critical_count = sum(
            1 for f in ws.findings
            if f.get("severity", "").lower() in ("critical", "high")
        )
        if critical_count:
            print(f"\n{c(RED, f'[!] {critical_count} finding(s) critique(s)/élevé(s) détecté(s).', bold=True)}")
            return 1
        return 0
    else:
        print(f"\n{c(WHITE, '[i] Aucun finding détecté.')}")
        return 0


# Boucle principale

def menu_loop(ws, url: str) -> int:
    """Retourne le code de sortie le plus grave observé pendant la session."""
    worst_exit = 0
    while True:
        print_menu()
        choice = input(f"\n{c(BLUE, '[?]')} {c(WHITE, 'Choisissez une option :')} ").strip()

        if choice in ("1", "2", "4", "5", "6"):
            exit_code = run_action(ws, choice)
            worst_exit = max(worst_exit, exit_code)
            if not ask_to_continue():
                break

        elif choice == "3":
            try:
                print(f"\n{c(BLUE, '[*] Crawling sur :')} {c(CYAN, url)}")
                ws.crawl()
                n = len(ws.link_list)
                print(f"\n{c(GREEN, f'[*] Crawling terminé - {n} URL(s) découverte(s).')}")
                for lnk in ws.link_list:
                    print(f"{c(CYAN, lnk)}")
            except KeyboardInterrupt:
                print(f"\n{c(YELLOW, '[!] Crawl interrompu.')}")

            if not ask_to_continue():
                break

        elif choice == "7":
            ans = input(f"\n{c(BLUE, '[?]')} {c(WHITE, 'Voulez-vous vérifier les mises à jour avant de quitter ? (o/N) : ')}").strip().lower()
            if ans in ("o", "oui", "y", "yes"):
                print(f"\n{c(BLUE, '[*]')} Recherche de mises à jour en cours...")
                import subprocess
                try:
                    result = subprocess.run(["git", "pull"], capture_output=True, text=True, check=True)
                    if "Already up to date" in result.stdout or "Déjà à jour" in result.stdout:
                        print(c(GREEN, "[+] WebMapper est déjà à la dernière version !"))
                    else:
                        print(c(GREEN, "[+] WebMapper a été mis à jour avec succès !"))
                        print(c(DIM + WHITE, result.stdout.strip()))
                except Exception as e:
                    print(c(RED, f"[!] Échec de la mise à jour. Erreur: {e}"))
            
            print(c(GREEN, "\n[*] Merci d'avoir utilisé WebMapper. À bientôt !"))
            break

        else:
            print(c(RED, "[!] Choix invalide."))

    return worst_exit


# Parsing des arguments CLI

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WebMapper - Scanner de vulnérabilités web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="URL cible (ex: http://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Nombre de threads parallèles (défaut: 5)")
    parser.add_argument("--proxy", type=str, default=None, help="Proxy HTTP (ex: http://127.0.0.1:8080)")
    parser.add_argument("--no-rotate-ua", action="store_true", help="Désactiver la rotation de User-Agent")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mode verbose (affiche les logs de debug)")
    
    # Options pour les modules spécifiques
    parser.add_argument("--wordlist", type=str, default=None, help="Chemin vers une wordlist custom pour l'énumération DNS")
    parser.add_argument("--ports", type=str, default=None, help="Ports à scanner (ex: '80,443')")
    parser.add_argument("--nuclei-args", type=str, default=None, help="Arguments supplémentaires à passer à Nuclei (ex: '-tags cve')")
    parser.add_argument("--update", action="store_true", help="Met à jour WebMapper via git pull et quitte")
    
    return parser.parse_args()


# Entrée 

def main() -> None:
    # Applique automatiquement la marge globale (margin/padding) à la console
    sys.stdout = MarginStdout(sys.stdout, margin=6)
    
    args = parse_args()

    if args.update:
        print(f"\n{c(BLUE, '[*]')} Recherche de mises à jour en cours...")
        import subprocess
        try:
            result = subprocess.run(["git", "pull"], capture_output=True, text=True, check=True)
            if "Already up to date" in result.stdout or "Déjà à jour" in result.stdout:
                print(c(GREEN, "[+] WebMapper est déjà à la dernière version !"))
            else:
                print(c(GREEN, "[+] WebMapper a été mis à jour avec succès !"))
                print(c(DIM + WHITE, result.stdout.strip()))
        except Exception as e:
            print(c(RED, f"[!] Échec de la mise à jour. Erreur: {e}"))
        sys.exit(0)

    # Configuration du logging sur stdout pour respecter la marge globale
    log_level = logging.DEBUG if args.verbose else logging.INFO
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    
    class FilterUrllib3(logging.Filter):
        def filter(self, record):
            # Masquer TOUS les logs d'urllib3 (même les warnings de retries)
            if record.name.startswith("urllib3"):
                return False
            return True
            
    handler.addFilter(FilterUrllib3())
    
    import datetime
    
    class CustomFormatter(logging.Formatter):
        def format(self, record):
            time_str = datetime.datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
            module = record.name
            msg = record.getMessage()
            # Simplification des erreurs techniques hideuses (urllib3/requests)
            if "HTTPConnectionPool" in msg or "Max retries exceeded" in msg:
                if "Network is unreachable" in msg:
                    msg = "Hôte inatteignable (IP bloquée par Pare-feu ou réseau coupé)"
                elif "Name or service not known" in msg:
                    msg = "Résolution DNS impossible (Domaine introuvable)"
                elif "Connection refused" in msg:
                    msg = "Connexion refusée par la cible"
                elif "timed out" in msg.lower() or "timeout" in msg.lower():
                    msg = "Délai d'attente dépassé (Timeout)"
                else:
                    msg = "Connexion interrompue par la cible"
                    
            # Couleurs
            C_TIME = "\033[38;5;214m"  # Orange jauné
            C_MOD  = "\033[38;5;39m"   # Bleu ciel
            C_SEP  = "\033[38;5;214m"  # Orange jauné
            C_VAL1 = "\033[97m"        # Blanc
            C_VAL2 = "\033[38;5;46m"   # Vert Émeraude
            C_ERR  = "\033[38;5;196m"  # Rouge (pour les erreurs)
            RESET  = "\033[0m"
            
            # Alignements
            mod_aligned = f"{module:<25}"
            
            if "Exécution Nmap :" in msg:
                parts = msg.split("Exécution Nmap :")
                return f"{C_TIME}{time_str}{RESET}  {C_MOD}{mod_aligned}{RESET}  \033[90mExécution Nmap :\033[0m \033[97m\033[1m{parts[1].strip()}\033[0m"

            if " → " in msg:
                parts = msg.split(" → ", 1)
                p1 = parts[0].strip()
                p2 = parts[1].strip()
                return f"{C_TIME}{time_str}{RESET}  {C_MOD}{mod_aligned}{RESET}  {C_VAL1}{p1:<28}{RESET} {C_SEP}→{RESET} {C_VAL2}{p2}{RESET}"
            
            # Fallback pour les messages standards
            if record.levelno >= logging.ERROR or "inatteignable" in msg or "impossible" in msg or "refusée" in msg or "Timeout" in msg:
                return f"{C_TIME}{time_str}{RESET}  {C_MOD}{mod_aligned}{RESET}  {C_ERR}{msg}{RESET}"
            return f"{C_TIME}{time_str}{RESET}  {C_MOD}{mod_aligned}{RESET}  \033[2m{msg}\033[0m"
            
    handler.setFormatter(CustomFormatter())
    
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = []
    root_logger.addHandler(handler)

    show_banner()

    # URL depuis l'argument CLI ou saisie interactive
    if not args.url:
        prompt = c(BLUE, "[?]") + " " + c(WHITE, "Entrez l'URL cible (ex: http://example.com) : ")
        args.url = input(prompt).strip()
        if not args.url:
            print(c(RED, "[!] URL requise."))
            sys.exit(1)

    # Validation stricte de l'URL (fix bug #1)
    result = validate_url(args.url)
    if not result.is_valid:
        print(c(RED, f"[!] URL invalide : {result.error}"))
        sys.exit(1)
    args.url = result.normalized_url

    # Construction du proxy dict si fourni
    proxy = None
    if args.proxy:
        proxy = {"http": args.proxy, "https": args.proxy}

    # Auto-détection HTTP/HTTPS
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print(c(BLUE, "[*] Vérification du protocole cible..."))
    try:
        res = requests.get(args.url, verify=False, proxies=proxy, timeout=5)  # nosec B501 ( Scanner requires invalid cert support )
        if args.url.startswith("http://") and "The plain HTTP request was sent to HTTPS port" in res.text:
            args.url = args.url.replace("http://", "https://", 1)
            print(c(YELLOW, f"[i] Port HTTPS détecté, correction automatique : {args.url}"))
    except requests.exceptions.SSLError:
        if args.url.startswith("https://"):
            args.url = args.url.replace("https://", "http://", 1)
            print(c(YELLOW, f"[i] Cible parle HTTP (Erreur SSL ignorée), correction automatique : {args.url}"))
    except requests.exceptions.ConnectionError:
        alt_url = args.url.replace("http://", "https://", 1) if args.url.startswith("http://") else args.url.replace("https://", "http://", 1)
        try:
            requests.get(alt_url, verify=False, proxies=proxy, timeout=5)  # nosec B501 ( Scanner requires invalid cert support )
            args.url = alt_url
            print(c(YELLOW, f"[i] Changement de protocole (HTTP/HTTPS) réussi : {args.url}"))
        except Exception:
            pass
    except Exception:
        pass

    print_config(args)

    ws = web_scanner.WebScanner(
        url=args.url,
        proxy=proxy,
        max_threads=args.threads,
        rotate_ua=not args.no_rotate_ua,
        wordlist=args.wordlist,
        ports_config=args.ports,
        nuclei_args=args.nuclei_args,
    )
    exit_code = menu_loop(ws, args.url)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()