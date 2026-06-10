#!/bin/bash
# install.sh

cd "$(dirname "$0")/../.." || exit

echo -e "\033[38;5;39m[*] Installation de WebMapper pour Linux...\033[0m"

# 1. Python & Venv
if ! command -v python3 &> /dev/null; then
    echo -e "\033[38;5;196m[!] Python3 n'est pas installé sur votre système.\033[0m"
    exit 1
fi

if [ ! -d "venv" ]; then
    echo -e "\033[38;5;39m[*] Création de l'environnement virtuel (venv)...\033[0m"
    python3 -m venv venv
fi

source venv/bin/activate
echo -e "\033[38;5;39m[*] Installation des dépendances Python...\033[0m"
pip install --upgrade pip
pip install -r requirements.txt

# 2. Vérification Nmap
if ! command -v nmap &> /dev/null; then
    echo -e "\033[38;5;220m[!] Nmap n'est pas installé.\033[0m"
    echo -n -e "Voulez-vous l'installer (nécessite sudo) ? (o/n) : "
    read -r resp
    if [ "$resp" = "o" ] || [ "$resp" = "O" ]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y nmap
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y nmap
        else
            echo -e "\033[38;5;220m[!] Gestionnaire de paquets inconnu. Veuillez installer nmap manuellement.\033[0m"
        fi
    fi
else
    echo -e "\033[38;5;46m[+] Nmap est déjà installé.\033[0m"
fi

# 3. Vérification Nuclei
if ! command -v nuclei &> /dev/null; then
    echo -e "\033[38;5;220m[!] Nuclei n'est pas installé.\033[0m"
    echo -n -e "Voulez-vous télécharger le binaire Nuclei dans /usr/local/bin ? (o/n) : "
    read -r resp
    if [ "$resp" = "o" ] || [ "$resp" = "O" ]; then
        echo -e "\033[38;5;39m[*] Téléchargement de Nuclei...\033[0m"
        if ! command -v unzip &> /dev/null; then
            echo "unzip requis. Tentative d'installation..."
            sudo apt-get install -y unzip || sudo dnf install -y unzip
        fi
        NUCLEI_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep "browser_download_url.*linux_amd64.zip" | cut -d '"' -f 4)
        if [ -n "$NUCLEI_URL" ]; then
            wget "$NUCLEI_URL" -O nuclei.zip
            unzip nuclei.zip nuclei
            sudo mv nuclei /usr/local/bin/
            rm nuclei.zip
            echo -e "\033[38;5;39m[*] Mise à jour des templates Nuclei...\033[0m"
            nuclei -update-templates
        else
            echo -e "\033[38;5;196m[!] Impossible de récupérer l'URL de téléchargement de Nuclei.\033[0m"
        fi
    fi
else
    echo -e "\033[38;5;46m[+] Nuclei est déjà installé.\033[0m"
fi

echo -e "\n\033[38;5;46m[+] Installation terminée ! \033[0m"
echo -e "\033[38;5;220m[*] Pour lancer WebMapper : ./webmapper.sh\033[0m"