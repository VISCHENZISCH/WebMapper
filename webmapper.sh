#!/bin/bash

# Lanceur spécial WebMapper CLI

# Vérifier si venv existe
if [ ! -d "venv" ]; then
    echo "[!] Environnement virtuel non détecté. Veuillez lancer ./install.sh d'abord."
    exit 1
fi

# Activer venv et lancer le script principal
source venv/bin/activate
python3 cli/main.py "$@"
