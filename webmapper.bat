@echo off
:: webmapper.bat
cd /d "%~dp0"

IF NOT EXIST "venv" (
    color 0C
    echo [!] Environnement virtuel non detecte. 
    echo [*] Veuillez lancer webmapper\scripts\install.bat au prealable.
    pause
    exit /b 1
)

call venv\Scripts\activate.bat
python webmapper\main.py %*
