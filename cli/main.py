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

# Couleurs classiques
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
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
    print("\t\t" + c(CYAN, 'https://github.com/VISCHENZISCH/WebMapper.git\n'))
  


def clear_terminal() -> None:
    os.system("cls" if os.name == "nt" else "clear")


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
    print(f"\n{c(BLUE, '[+] Rapports générés :')}")
    print(f"    {c(WHITE, 'HTML')}  : {c(CYAN, paths.get('html', '-'))}")
    print(f"    {c(WHITE, 'JSON')}  : {c(CYAN, paths.get('json', '-'))}")
    print(f"    {c(WHITE, 'CSV')}   : {c(CYAN, paths.get('csv',  '-'))}")
    print(f"    {c(WHITE, 'SARIF')} : {c(CYAN, paths.get('sarif', '-'))}")


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


# Menu 

def print_menu() -> None:
    items = [
        ("1", "Scan Complet",       "FULL", "Crawl + tous les modules"),
        ("2", "Scan Direct",        "FAST", "URL cible uniquement, sans crawl"),
        ("3", "Crawler uniquement", "MAP",  "Découverte de liens"),
        ("4", "Quitter",            "",     ""),
    ]
    print(f"\n{c(YELLOW, '║  Utilisation réservée aux tests autorisés uniquement.')}\n")
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

        if choice in ("1", "2"):
            exit_code = run_action(ws, choice)
            worst_exit = max(worst_exit, exit_code)
            if not ask_to_continue():
                break

        elif choice == "3":
            try:
                print(f"\n{c(BLUE, '[*] Crawling sur :')} {c(CYAN, url)}")
                ws.crawl()
                n = len(ws.link_list)
                print(f"\n{c(GREEN, f'[*] Crawling terminé — {n} URL(s) découverte(s).')}")
                for lnk in ws.link_list:
                    print(f"   {c(CYAN, lnk)}")
            except KeyboardInterrupt:
                print(f"\n{c(YELLOW, '[!] Crawl interrompu.')}")

            if not ask_to_continue():
                break

        elif choice == "4":
            print(c(GREEN, "[*] Merci d'avoir utilisé WebMapper. À bientôt !"))
            break

        else:
            print(c(RED, "[!] Choix invalide."))

    return worst_exit


# Parsing des arguments CLI

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WebMapper — Scanner de vulnérabilités web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="URL cible (ex: http://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Nombre de threads parallèles (défaut: 5)")
    parser.add_argument("--proxy", type=str, default=None, help="Proxy HTTP (ex: http://127.0.0.1:8080)")
    parser.add_argument("--no-rotate-ua", action="store_true", help="Désactiver la rotation de User-Agent")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mode verbose (affiche les logs de debug)")
    return parser.parse_args()


# Entrée 

def main() -> None:
    args = parse_args()

    # Configuration du logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="\033[2m%(name)s — %(message)s\033[0m",
    )

    show_banner()

    # URL depuis l'argument CLI ou saisie interactive
    if not args.url:
        prompt = c(BLUE, "[?]") + " " + c(WHITE, "Entrez l'URL cible (ex: http://example.com) : ")
        args.url = input(prompt).strip()
        if not args.url:
            print(c(RED, "[!] URL requise."))
            sys.exit(1)

    # Construction du proxy dict si fourni
    proxy = None
    if args.proxy:
        proxy = {"http": args.proxy, "https": args.proxy}

    print_config(args)

    ws = web_scanner.WebScanner(
        url=args.url,
        proxy=proxy,
        max_threads=args.threads,
        rotate_ua=not args.no_rotate_ua,
    )
    exit_code = menu_loop(ws, args.url)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()