#!/bin/bash
# webmapper.sh

cd "$(dirname "$0")" || exit

if [ ! -d "venv" ]; then
    echo -e "\033[38;5;196m[!] Environnement virtuel non détecté.\033[0m"
    echo -e "\033[38;5;220m[*] Veuillez lancer ./webmapper/scripts/install.sh au préalable.\033[0m"
    exit 1
fi

source venv/bin/activate
python3 webmapper/main.py "$@"
