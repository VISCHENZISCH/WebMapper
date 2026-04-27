@echo off
setlocal enabledelayedexpansion

cls

echo.
echo + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - 
echo ║    WebMapper Installation              ║
echo ║    © 2025 Félix TOVIGNAN               ║
echo + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - 
echo.

REM Vérifier Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  Python n'est pas installé!
    echo Télécharge Python depuis https://www.python.org
    pause
    exit /b 1
)

echo  Python trouvé
echo [*] Création de l'environnement virtuel...
echo.

REM Créer l'environnement virtuel
if exist venv (
    echo [!] Un environnement virtuel existe déjà
    set /p reinit="Réinitialiser? (o/n): "
    if /i "!reinit!"=="o" (
        rmdir /s /q venv
        python -m venv venv
    )
) else (
    python -m venv venv
)

REM Activer l'environnement
echo [*] Activation de l'environnement virtuel...
call venv\Scripts\activate.bat

REM Upgrade pip
echo [*] Mise à jour de pip...
python -m pip install --upgrade pip setuptools wheel >nul 2>&1

REM Installer les dépendances
echo [*] Installation des dépendances...
pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo.
    echo  Erreur lors de l'installation des dépendances
    pause
    exit /b 1
)

echo.
echo + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - 
echo ║    Installation réussie!               ║
echo + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - + - 
echo.
echo  Utiliser webmapper.bat:
echo   webmapper.bat https://example.com
echo.
echo Prêt à scanner!
echo.
pause
