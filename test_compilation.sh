#!/bin/bash

# Script de test de compilation pour ESP32 Reverse SSH Tunnel Library
# Usage: ./test_compilation.sh

echo "=== ESP32 Reverse SSH Tunnel Library - Test de compilation ==="
echo ""

# Vérifier si PlatformIO est installé
if ! command -v pio &> /dev/null; then
    echo "❌ PlatformIO n'est pas installé. Installation en cours..."
    pip install platformio
    if [ $? -ne 0 ]; then
        echo "❌ Échec de l'installation de PlatformIO"
        exit 1
    fi
fi

echo "✅ PlatformIO est installé"

# Aller dans le dossier examples
cd examples

# Nettoyer les builds précédents
echo "🧹 Nettoyage des builds précédents..."
pio run --target clean

# Vérifier la configuration du projet
echo "🔧 Vérification de la configuration du projet..."
pio project config

# Installer les dépendances
echo "📦 Installation des dépendances..."
pio pkg install

# Compiler pour ESP32
echo "🔨 Compilation pour ESP32..."
pio run -e esp32dev

# Vérifier le résultat
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Compilation réussie !"
    echo ""
    echo "📊 Informations sur le build:"
    pio run -e esp32dev --target size
    echo ""
    echo "📁 Fichiers générés:"
    ls -la .pio/build/esp32dev/
else
    echo ""
    echo "❌ Échec de la compilation"
    echo ""
    echo "🔍 Vérification des erreurs:"
    pio run -e esp32dev --verbose
    exit 1
fi

echo ""
echo "🎉 Test de compilation terminé avec succès !"
