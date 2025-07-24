#!/bin/bash
# Script de test de compilation pour libssh2_esp

echo "=== Test de Compilation libssh2_esp ==="
echo "Date: $(date)"
echo ""

# Vérifier si PlatformIO est installé
if ! command -v pio &> /dev/null; then
    echo "❌ PlatformIO n'est pas installé ou pas dans le PATH"
    echo "Installez PlatformIO avec: pip install platformio"
    exit 1
fi

echo "✅ PlatformIO trouvé: $(pio --version)"
echo ""

# Aller dans le dossier examples
cd examples || {
    echo "❌ Impossible d'accéder au dossier examples"
    exit 1
}

echo "📁 Dossier de travail: $(pwd)"
echo ""

# Nettoyer les builds précédents
echo "🧹 Nettoyage des builds précédents..."
rm -rf .pio/build
rm -rf .pio/libdeps

# Afficher la configuration
echo "📋 Configuration PlatformIO:"
echo "----------------------------------------"
cat platformio.ini
echo "----------------------------------------"
echo ""

# Test 1: Vérification de la syntaxe
echo "🔍 Test 1: Vérification de la syntaxe..."
pio check --verbose 2>&1 | tee check.log

# Test 2: Compilation complète
echo ""
echo "🔨 Test 2: Compilation complète..."
echo "Cela peut prendre plusieurs minutes pour télécharger libssh2_esp..."

# Capturer le temps de début
start_time=$(date +%s)

# Lancer la compilation avec sortie détaillée
pio run --verbose 2>&1 | tee build.log

# Capturer le code de retour
build_result=$?
end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo "⏱️  Durée de compilation: ${duration} secondes"
echo ""

# Analyser les résultats
if [ $build_result -eq 0 ]; then
    echo "✅ SUCCÈS: La compilation a réussi!"
    echo ""
    echo "📊 Informations sur le firmware:"
    echo "----------------------------------------"
    
    # Afficher les informations sur le firmware si disponible
    if [ -f ".pio/build/esp32dev/firmware.bin" ]; then
        ls -lh .pio/build/esp32dev/firmware.bin
        echo "Taille du firmware: $(stat -f%z .pio/build/esp32dev/firmware.bin 2>/dev/null || stat -c%s .pio/build/esp32dev/firmware.bin) bytes"
    fi
    
    echo "----------------------------------------"
    echo ""
    echo "🎉 Votre projet compile correctement avec libssh2_esp!"
    echo "Vous pouvez maintenant flasher le firmware sur votre ESP32."
    
else
    echo "❌ ÉCHEC: La compilation a échoué"
    echo ""
    echo "🔍 Analyse des erreurs:"
    echo "----------------------------------------"
    
    # Extraire les erreurs principales du log
    if [ -f "build.log" ]; then
        echo "Erreurs de compilation trouvées:"
        grep -E "(error|fatal error|undefined reference)" build.log | head -10
        echo ""
        
        # Vérifier les erreurs spécifiques à libssh2
        if grep -q "libssh2.h.*No such file" build.log; then
            echo "🚨 Problème détecté: libssh2.h non trouvé"
            echo "Solutions possibles:"
            echo "1. Vérifier la connexion Internet pour télécharger libssh2_esp"
            echo "2. Essayer de nettoyer complètement: pio system prune"
            echo "3. Vérifier l'URL du repository dans platformio.ini"
        fi
        
        if grep -q "undefined reference.*libssh2" build.log; then
            echo "🚨 Problème détecté: Symboles libssh2 non liés"
            echo "Solutions possibles:"
            echo "1. Vérifier que libssh2_esp compile correctement"
            echo "2. Ajouter des flags de linkage spécifiques"
        fi
    fi
    
    echo "----------------------------------------"
    echo ""
    echo "📝 Logs sauvegardés dans:"
    echo "  - build.log (compilation complète)"
    echo "  - check.log (vérification syntaxe)"
fi

echo ""
echo "=== Fin du test ==="
