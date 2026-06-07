@echo off
chcp 65001 > nul

if not exist "venv" (
    echo [!] Environnement virtuel non détecté. Veuillez lancer install.bat d'abord.
    pause
    exit /b 1
)

call venv\Scripts\activate
python cli\main.py %*
