#!/bin/bash

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}+ - + - + - + - + - + - + - + - + - + - + ${NC}"
echo -e "${BLUE}║        WebMapper Installation         ║${NC}"
echo -e "${BLUE}║         © 2025 Félix TOVIGNAN         ║${NC}"
echo -e "${BLUE}+ - + - + - + - + - + - + - + - + - + - + ${NC}"
echo -e "${NC}"

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED} Python 3 n'est pas installé!${NC}"
    echo "Installe Python 3.8+ depuis https://www.python.org"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}[+] Python trouvé: $PYTHON_VERSION${NC}"

# Vérifier la version Python
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo -e "${RED} Python 3.8+ requis (tu as $PYTHON_VERSION)${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}[*] Création de l'environnement virtuel...${NC}"

# Créer l'environnement virtuel
if [ -d "venv" ]; then
    echo -e "${YELLOW}[!] Un environnement virtuel existe déjà${NC}"
    read -p "Voulez-vous le réinitialiser? (o/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Oo]$ ]]; then
        rm -rf venv
        python3 -m venv venv
    fi
else
    python3 -m venv venv
fi

# Activer l'environnement virtuel
echo -e "${YELLOW}[*] Activation de l'environnement virtuel...${NC}"
source venv/bin/activate

# Upgrade pip
echo -e "${YELLOW}[*] Mise à jour de pip...${NC}"
pip install --upgrade pip setuptools wheel > /dev/null 2>&1

# Vérifier requirements.txt
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED} requirements.txt non trouvé!${NC}"
    exit 1
fi

# Installer les dépendances
echo -e "${BLUE}+ - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - ${NC}"
echo -e "${YELLOW}[*] Installation des dépendances...${NC}"
pip install -r requirements.txt

# Vérifier les fichiers essentiels
echo -e "${YELLOW}[*] Vérification des fichiers...${NC}"

if [ ! -f "cli/main.py" ]; then
    echo -e "${RED} cli/main.py non trouvé!${NC}"
    exit 1
fi

if [ ! -f "webmapper.sh" ]; then
    echo -e "${RED} webmapper.sh non trouvé!${NC}"
    exit 1
fi

# Rendre webmapper.sh exécutable
chmod +x webmapper.sh

echo ""
echo -e "${GREEN}+ - + - + - + - + - + - + - + - + - + - + - + ${NC}"
echo -e "${GREEN}║              Installation réussie!        ║${NC}"
echo -e "${GREEN}+ - + - + - + - + - + - + - + - + - + - + - + ${NC}"
echo ""
echo -e "${BLUE} Prochaines étapes:${NC}"
echo ""
echo -e "${YELLOW}Option 1 - Voir l'aide:${NC}"
echo "  ./webmapper.sh --help"
echo ""
echo -e "${BLUE} Documentation:${NC}"
echo "  README.md         -         Aperçu du projet"
echo ""
echo -e "${GREEN}Prêt à scanner! ${NC}"
echo -e "${BLUE}+ - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - ${NC}"