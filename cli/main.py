#!/usr/bin/env python3
# coding:utf-8

import sys
import os
import web_scanner
from reports.reporter import Reporter


def show_banner():
    banner = """
    \033[92m\033[1m
    __      __      ___.   _____                                             
    /  \\    /  \\ ____\\_ |__ /     \\ _____  ______ ______   ___________ 
    \\   \\/\\/   // __ \\| __ \\  \\ /  \\\\__  \\ \\____ \\\\____ \\_/ __ \\_  __ \\
     \\        /\\  ___/| \\_\\ \\   Y  / / __ \\|  |_> >  |_> >\\  ___/|  | \\/
      \\__/\\  /  \\___  >___  /__|_|  /(____  /   __/|   __/  \\___  >__|   
           \\/       \\/    \\/      \\/      \\/|__|   |__|         \\/       
    \033[0m
    \033[92m\033[1mWebMapper v1.0   --------------------------------------  CLI Edition\033[0m
                                \033[33m© 2025 Félix TOVIGNAN\033[0m
                    \033[96mhttps://github.com/VISCHENZISCH/WebMapper.git\033[0m
    """
    print(banner)

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def ask_to_continue():
    print("\n" + "\033[94m+ - \033[0m"*25)
    choice = input("\033[94m[?]\033[0m Voulez-vous continuer à utiliser WebMapper ? (o/n) : ").lower()
    if choice == 'o':
        clear_terminal()
        show_banner()
        return True
    
    print("\n\033[92m[*] Merci d'avoir utilisé WebMapper. À bientôt !\033[0m")
    return False

def main():
    show_banner()
    if len(sys.argv) < 2:
        url = input("\033[94m[?]\033[0m \033[97mEntrez l'URL cible (ex: http://example.com) :\033[0m ")
        if not url:
            print("\033[91m[!] Erreur: Une URL est requise.\033[0m")
            sys.exit(1)
    else:
        url = sys.argv[1]

    ws = web_scanner.WebScanner(url)

    while True:
        print(f"\n\033[93m║  Utilisation réservée aux tests autorisés.          ")
        print(f"║  Toute utilisation non autorisée est illégale.      \033[0m")
        print(f"\n\033[94m[ ✔✘!?→ ] \033[91m\033[1m════════════════════ \033[92m\033[1mMENU DE SCAN\033[0m \033[91m\033[1m════════════════════\033[0m \033[94m[ ✔✘!?→ ]\033[0m\n")
        print("1. \033[94m\033[1mScan Complet\033[0m \033[97m(Crawl + Vulnérabilités)\033[0m")
        print("2. \033[94m\033[1mCrawler uniquement\033[0m \033[97m(Découverte de liens)\033[0m")
        print("3. \033[94m\033[1mAnalyse de vulnérabilités\033[0m \033[97m(Sur l'URL cible)\033[0m")
        print("4. \033[94m\033[1mAnalyse des cookies\033[0m \033[97m(Audit de sécurité)\033[0m")
        print("5. \033[97mQuitter\033[0m")
        
        choice = input("\n\033[94m[?]\033[0m \033[97mChoisissez une option :\033[0m ")

        if choice == "1":
            try:
                print(f"\n\033[94m[*] Début du scan complet sur :\033[0m \033[96m{url}\033[0m")
                ws.crawl()
                ws.check_vulnerabilities()
                print("\n\033[92m[*] Scan complet terminé.\033[0m")
            except KeyboardInterrupt:
                print("\n\033[93m[!] Scan interrompu par l'utilisateur. Exportation des données partielles...\033[0m")
            
            # Génération des rapports (toujours, même si interrompu)
            if ws.results_list:
                paths = Reporter.generate_all(ws.results_list, "full_scan")
                print(f"\n\033[94m[+] Rapports générés :\033[0m")
                print(f"    - HTML : {paths['html']}")
                print(f"    - JSON : {paths['json']}")
                print(f"    - CSV  : {paths['csv']}")
            else:
                print("\n\033[97m[i] Aucun résultat à exporter.\033[0m")
            
            if not ask_to_continue(): break

        elif choice == "2":
            try:
                print(f"\n\033[94m[*] Lancement du crawler sur :\033[0m \033[96m{url}\033[0m")
                ws.crawl()
                print("\n\033[92m[*] Crawling terminé.\033[0m")
            except KeyboardInterrupt:
                print("\n\033[93m[!] Crawling interrompu.\033[0m")
            if not ask_to_continue(): break

        elif choice == "3":
            try:
                print(f"\n\033[94m[*] Analyse de vulnérabilités sur :\033[0m \033[96m{url}\033[0m")
                ws.link_list = [url]
                ws.check_vulnerabilities()
                print("\n\033[92m[*] Analyse terminée.\033[0m")
            except KeyboardInterrupt:
                print("\n\033[93m[!] Analyse interrompue. Exportation des données...\033[0m")
            
            if ws.results_list:
                paths = Reporter.generate_all(ws.results_list, "vuln_scan")
                print(f"\n\033[94m[+] Rapports générés :\033[0m")
                print(f"    - HTML : {paths['html']}")
            if not ask_to_continue(): break

        elif choice == "4":
            try:
                print(f"\n\033[94m[*] Audit de sécurité des cookies sur :\033[0m \033[96m{url}\033[0m")
                ws.check_cookies()
                print("\n\033[92m[*] Analyse des cookies terminée.\033[0m")
            except KeyboardInterrupt:
                print("\n\033[93m[!] Audit interrompu.\033[0m")
            
            if ws.results_list:
                paths = Reporter.generate_all(ws.results_list, "cookie_audit")
                print(f"\n\033[94m[+] Rapports générés :\033[0m")
                print(f"    - HTML : {paths['html']}")
            if not ask_to_continue(): break
        elif choice == "5":
            print("\033[92m[*] Merci d'avoir utilisé WebMapper. À bientôt !\033[0m")
            sys.exit(0)
        else:
            print("\033[91m[!] Choix invalide.\033[0m")

if __name__ == "__main__":
    main()