# Infos de test pour le Web Scanner

# Cibles de test :
# - Metasploitable
#Exemple: http://exemple.com

import sys
import os

# Ajouter le dossier parent au path pour importer 'cli' si besoin
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'cli')))

import web

def run_test():
    #url = "http://Metasploitable[IP_ADDRESS]"
    url = "http://exemple.com"
    print(f"Lancement du test sur : {url}")
    wc = web.WebCrawler(url)
    wc.crawl()

if __name__ == "__main__":
    run_test()
