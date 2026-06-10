#!/bin/bash
# update.sh

cd "$(dirname "$0")/../.." || exit

echo -e "\033[38;5;39m[*] Début de la mise à jour de WebMapper...\033[0m"

echo -e "\n\033[38;5;39m[*] Synchronisation Git (pull)...\033[0m"
git pull origin main

if [ -d "venv" ]; then
    echo -e "\n\033[38;5;39m[*] Mise à jour des librairies Python...\033[0m"
    source venv/bin/activate
    pip install -r requirements.txt --upgrade
fi

if command -v nuclei &> /dev/null; then
    echo -e "\n\033[38;5;39m[*] Mise à jour des signatures Nuclei...\033[0m"
    nuclei -update-templates
fi

echo -e "\n\033[38;5;46m[+] Mise à jour terminée !\033[0m"
