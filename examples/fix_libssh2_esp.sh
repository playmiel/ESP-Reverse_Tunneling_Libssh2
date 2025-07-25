#!/bin/bash

# Script pour corriger automatiquement les problèmes de compilation avec libssh2_esp
# Usage: ./fix_libssh2_esp.sh

echo "🔧 Script de correction pour libssh2_esp"
echo "========================================"

# Vérifier si nous sommes dans le bon répertoire
if [ ! -f "platformio.ini" ]; then
    echo "❌ Erreur: Ce script doit être exécuté depuis le dossier examples/"
    echo "   (le répertoire contenant platformio.ini)"
    exit 1
fi

echo "📁 Nettoyage des répertoires problématiques..."

# Supprimer les répertoires d'exemples et tests qui causent des erreurs
LIBSSH2_PATH=".pio/libdeps/esp32dev/libssh2_esp"

if [ -d "$LIBSSH2_PATH" ]; then
    echo "   - Suppression des exemples libssh2..."
    rm -rf "$LIBSSH2_PATH/libssh2/example" 2>/dev/null
    rm -rf "$LIBSSH2_PATH/examples" 2>/dev/null
    
    echo "   - Suppression des tests..."
    rm -rf "$LIBSSH2_PATH/libssh2/tests" 2>/dev/null
    
    echo "   - Suppression des répertoires spécifiques aux plateformes..."
    rm -rf "$LIBSSH2_PATH/libssh2/os400" 2>/dev/null
    rm -rf "$LIBSSH2_PATH/libssh2/vms" 2>/dev/null
    rm -rf "$LIBSSH2_PATH/libssh2/win32" 2>/dev/null
    
    echo "   - Suppression de tous les fichiers OS/400 restants..."
    find "$LIBSSH2_PATH" -name "*os400*" -type f -delete 2>/dev/null
    find "$LIBSSH2_PATH" -name "*qtqiconv*" -type f -delete 2>/dev/null
    find "$LIBSSH2_PATH" -name "*qadrt*" -type f -delete 2>/dev/null
    find "$LIBSSH2_PATH" -name "ccsid.c" -delete 2>/dev/null
    find "$LIBSSH2_PATH" -name "os400sys.c" -delete 2>/dev/null
    
    echo "✅ Nettoyage terminé"
else
    echo "⚠️  Répertoire libssh2_esp non trouvé - la dépendance n'est peut-être pas encore téléchargée"
fi

echo ""
echo "🔍 Vérification de la configuration..."

# Vérifier que platformio.ini contient les bonnes configurations
if grep -q "LIBSSH2_MBEDTLS" platformio.ini; then
    echo "✅ Configuration mbedTLS trouvée"
else
    echo "❌ Configuration mbedTLS manquante dans platformio.ini"
fi

if grep -q "libssh2/include" platformio.ini; then
    echo "✅ Chemins d'inclusion configurés"
else
    echo "❌ Chemins d'inclusion manquants dans platformio.ini"
fi

echo ""
echo "🧪 Test de compilation..."

if pio run --silent; then
    echo "✅ Compilation réussie !"
    echo ""
    echo "📊 Utilisation mémoire:"
    pio run 2>/dev/null | grep -E "(RAM|Flash):"
else
    echo "❌ Échec de la compilation"
    echo ""
    echo "🔧 Actions recommandées:"
    echo "   1. Vérifiez que platformio.ini contient la configuration correcte"
    echo "   2. Nettoyez le cache: pio run --target clean"
    echo "   3. Relancez ce script après le téléchargement des dépendances"
    echo ""
    echo "📖 Consultez ../SOLUTION_LIBSSH2_ESP.md pour plus de détails"
fi

echo ""
echo "🎯 Script terminé"
echo "   Pour plus d'informations, consultez ../SOLUTION_LIBSSH2_ESP.md"