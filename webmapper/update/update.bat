@echo off
:: update.bat
color 0B
cd /d "%~dp0\..\.."

echo [*] Debut de la mise a jour de WebMapper...

echo.
echo [*] Synchronisation Git (pull)...
git pull origin main

IF EXIST "venv" (
    echo.
    echo [*] Mise a jour des librairies Python...
    call venv\Scripts\activate.bat
    pip install -r requirements.txt --upgrade
)

nuclei -version >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    echo.
    echo [*] Mise a jour des signatures Nuclei...
    nuclei -update-templates
)

echo.
echo [+] Mise a jour terminee !
pause
