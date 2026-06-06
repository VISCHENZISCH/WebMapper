#!/usr/bin/env python3
# coding:utf-8
"""
WebMapper CLI
"""
import sys
import os
import web_scanner
from reports.reporter import Reporter


#Constantes ANSI 

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"


#Helpers

def c(color: str, text: str, bold: bool = False) -> str:
    """Applique une couleur ANSI à un texte."""
    return f"{BOLD if bold else ''}{color}{text}{RESET}"


def show_banner() -> None:
    print(f"""{BLUE}{BOLD}
    __      __      ___. _____                                          
   /  \\    /  \\ ____\\_ |__/     \\ _____  ______ ______   ___________  
   \\   \\/\\/   // __ \\| __ \\  \\ /  \\\\__  \\ \\____ \\\\____ \\_/ __ \\_  __ \\
    \\        /\\  ___/| \\_\\ \\   Y  / / __ \\|  |_> >  |_> >\\  ___/|  | \\/
     \\__/\\  /  \\___  >___  /__|_|  /(____  /   __/|   __/  \\___  >__|   
          \\/       \\/    \\/      \\/      \\/|__|   |__|         \\/       
{RESET}
{c(GREEN, 'WebMapper v1.0', bold=True)}   {c(DIM + WHITE, '---------------------------------------------')}  {c(GREEN, 'CLI Edition', bold=True)}
                          {c(YELLOW, '© 2025 Félix TOVIGNAN')}
              {c(CYAN, 'https://github.com/VISCHENZISCH/WebMapper.git')}
""")


def clear_terminal() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def ask_to_continue() -> bool:
    print("\n" + c(BLUE, "+ - ") * 25)
    choice = input(f"{c(BLUE, '[?]')} Continuer à utiliser WebMapper ? (o/n) : ").strip().lower()
    if choice == "o":
        clear_terminal()
        show_banner()
        return True
    print(f"\n{c(GREEN, '[*] Merci d\'avoir utilisé WebMapper. À bientôt !')}")
    return False


def print_report_paths(paths: dict) -> None:
    print(f"\n{c(BLUE, '[+] Rapports générés :')}")
    print(f"    {c(WHITE, 'HTML')} : {c(CYAN, paths.get('html', '-'))}")
    print(f"    {c(WHITE, 'JSON')} : {c(CYAN, paths.get('json', '-'))}")
    print(f"    {c(WHITE, 'CSV')}  : {c(CYAN, paths.get('csv',  '-'))}")


#Menu 

def print_menu() -> None:
    items = [
        ("1", "Scan Complet",       "FULL", "Crawl + tous les modules"),
        ("2", "Scan Direct",        "FAST", "URL cible uniquement, sans crawl"),
        ("3", "Crawler uniquement", "MAP",  "Découverte de liens"),
        ("4", "Quitter",            "",     ""),
    ]
    print(f"\n{c(YELLOW, '║  Utilisation réservée aux tests autorisés uniquement.')}")
    sep = c(RED, "══════════════", bold=True)
    print(f"{c(BLUE, '[ ✔✘!?→ ]')} {sep} {c(GREEN, 'MENU DE SCAN', bold=True)} {sep} {c(BLUE, '[ ✔✘!?→ ]')}\n")
    for num, label, badge, desc in items:
        badge_str = f" {c(CYAN, f'[{badge}]')}" if badge else ""
        desc_str  = f"  {c(DIM + WHITE, desc)}" if desc else ""
        print(f"  {c(BLUE, num, bold=True)}.  {c(WHITE, label, bold=True)}{badge_str}{desc_str}")


#Dispatcher

ACTIONS = {
    "1": ("run_full_scan",  "full_scan",   "Scan complet"),
    "2": ("run_vuln_scan",  "direct_scan", "Analyse directe"),
}


def run_action(ws, action_key: str) -> None:
    method_name, report_key, label = ACTIONS[action_key]
    try:
        getattr(ws, method_name)()
        print(f"\n{c(GREEN, f'[*] {label} terminé.')}")
    except KeyboardInterrupt:
        print(f"\n{c(YELLOW, '[!] Scan interrompu.')}")

    if ws.findings:
        paths = Reporter.generate_all(ws.findings, report_key)
        print_report_paths(paths)
    else:
        print(f"\n{c(WHITE, '[i] Aucun finding détecté.')}")


#Boucle principale

def menu_loop(ws, url: str) -> None:
    while True:
        print_menu()
        choice = input(f"\n{c(BLUE, '[?]')} {c(WHITE, 'Choisissez une option :')} ").strip()

        if choice in ("1", "2"):
            run_action(ws, choice)
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
            sys.exit(0)

        else:
            print(c(RED, "[!] Choix invalide."))


#Entrée 

def main() -> None:
    show_banner()

    # URL depuis l'argument CLI ou saisie interactive
    if len(sys.argv) >= 2:
        url = sys.argv[1]
    else:
        url = input(f"{c(BLUE, '[?]')} {c(WHITE, 'Entrez l\'URL cible (ex: http://example.com) :')} ").strip()
        if not url:
            print(c(RED, "[!] URL requise."))
            sys.exit(1)

    ws = web_scanner.WebScanner(url)
    menu_loop(ws, url)


if __name__ == "__main__":
    main()