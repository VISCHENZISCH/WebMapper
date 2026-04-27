@echo off
if not exist "venv" (
    echo [!] Environnement virtuel non detecte. Veuillez lancer install.bat d'abord.
    pause
    exit /b 1
)

call venv\Scripts\activate
python cli\main.py %*
