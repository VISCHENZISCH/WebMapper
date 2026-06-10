@echo off
:: install.bat
color 0B

cd /d "%~dp0\..\.."

echo [*] Installation de WebMapper pour Windows...

:: 1. Python
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [!] Python n'est pas installe ou n'est pas defini dans le PATH.
    pause
    exit /b 1
)

:: 2. Venv
IF NOT EXIST "venv" (
    echo [*] Creation de l'environnement virtuel (venv)...
    python -m venv venv
)

echo [*] Activation de l'environnement virtuel et installation des dependances Python...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt

:: 3. Outils externes
echo.
echo =====================================================================
echo [i] Outils de Securite Optionnels Recommandes :
echo =====================================================================
echo Nmap   : Requis pour le scan de ports (https://nmap.org/download.html)
echo Nuclei : Requis pour les templates de vulnerabilites (https://github.com/projectdiscovery/nuclei)
echo.

echo [+] Installation terminee !
echo [*] Pour lancer le scanner : webmapper.bat
pause
