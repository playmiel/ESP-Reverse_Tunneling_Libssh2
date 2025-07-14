@echo off
REM Script de test de compilation pour ESP32 Reverse SSH Tunnel Library (Windows)
REM Usage: test_compilation.bat

echo === ESP32 Reverse SSH Tunnel Library - Test de compilation ===
echo.

REM Vérifier si PlatformIO est installé
where pio >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ PlatformIO n'est pas installé. Installation en cours...
    pip install platformio
    if %errorlevel% neq 0 (
        echo ❌ Échec de l'installation de PlatformIO
        exit /b 1
    )
)

echo ✅ PlatformIO est installé

REM Aller dans le dossier examples
cd examples

REM Nettoyer les builds précédents
echo 🧹 Nettoyage des builds précédents...
pio run --target clean

REM Vérifier la configuration du projet
echo 🔧 Vérification de la configuration du projet...
pio project config

REM Installer les dépendances
echo 📦 Installation des dépendances...
pio pkg install

REM Compiler pour ESP32
echo 🔨 Compilation pour ESP32...
pio run -e esp32dev

REM Vérifier le résultat
if %errorlevel% equ 0 (
    echo.
    echo ✅ Compilation réussie !
    echo.
    echo 📊 Informations sur le build:
    pio run -e esp32dev --target size
    echo.
    echo 📁 Fichiers générés:
    dir .pio\build\esp32dev\
) else (
    echo.
    echo ❌ Échec de la compilation
    echo.
    echo 🔍 Vérification des erreurs:
    pio run -e esp32dev --verbose
    exit /b 1
)

echo.
echo 🎉 Test de compilation terminé avec succès !
pause
