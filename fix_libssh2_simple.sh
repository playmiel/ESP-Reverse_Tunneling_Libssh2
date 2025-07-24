#!/bin/bash

# Script simple pour corriger automatiquement la configuration libssh2_esp
# Usage: ./fix_libssh2_simple.sh [chemin_vers_platformio.ini]

PLATFORMIO_INI="${1:-platformio.ini}"

echo "🔧 Script de correction simple pour libssh2_esp"
echo "=============================================="
echo "📄 Fichier platformio.ini: $PLATFORMIO_INI"
echo ""

# Vérifier si le fichier platformio.ini existe
if [ ! -f "$PLATFORMIO_INI" ]; then
    echo "❌ Erreur: Fichier $PLATFORMIO_INI non trouvé"
    echo "   Assurez-vous d'être dans le bon répertoire ou spécifiez le chemin correct"
    exit 1
fi

# Créer une sauvegarde
BACKUP_FILE="${PLATFORMIO_INI}.backup.$(date +%Y%m%d_%H%M%S)"
cp "$PLATFORMIO_INI" "$BACKUP_FILE"
echo "💾 Sauvegarde créée: $BACKUP_FILE"

# Détecter la section [env:xxx] existante
ENV_SECTION=$(grep -o '^\[env:[^]]*\]' "$PLATFORMIO_INI" | head -1)
if [ -z "$ENV_SECTION" ]; then
    ENV_SECTION="[env:esp32dev]"
    echo "⚠️  Aucune section [env:] trouvée, utilisation de $ENV_SECTION par défaut"
fi

# Extraire les lib_deps existantes
EXISTING_LIBS=""
if grep -q "lib_deps" "$PLATFORMIO_INI"; then
    echo "📦 Détection des lib_deps existantes..."
    # Extraire les lib_deps en préservant les URLs GitHub
    EXISTING_LIBS=$(awk '/^lib_deps/,/^[[:space:]]*$/ {
        if (/^lib_deps/) next
        if (/^[[:space:]]*$/) exit
        if (/^[[:space:]]*[^[:space:]]/) print "    " $0
    }' "$PLATFORMIO_INI")
    
    # Si pas de libssh2_esp, l'ajouter
    if ! echo "$EXISTING_LIBS" | grep -q "libssh2"; then
        EXISTING_LIBS="    https://github.com/skuodi/libssh2_esp.git"$'\n'"$EXISTING_LIBS"
    fi
else
    EXISTING_LIBS="    https://github.com/skuodi/libssh2_esp.git"
fi

echo "🔧 Génération de la configuration corrigée..."

# Créer le nouveau fichier platformio.ini
cat > "$PLATFORMIO_INI" << EOF
$ENV_SECTION
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200

; Dépendance libssh2_esp pour le support SSH
lib_deps =
$EXISTING_LIBS

; Configuration pour libssh2_esp - exclure les exemples et plateformes non-ESP32
lib_ignore =
    libssh2_esp/libssh2/example
    libssh2_esp/libssh2/tests
    libssh2_esp/libssh2/docs
    libssh2_esp/libssh2/os400
    libssh2_esp/libssh2/win32
    libssh2_esp/libssh2/vms

; Filtres de source pour éviter la compilation des exemples et plateformes non-ESP32
build_src_filter =
    +<*>
    -<.git/>
    -<.svn/>
    -<example/>
    -<examples/>
    -<test/>
    -<tests/>
    -<docs/>
    -<os400/>
    -<win32/>
    -<vms/>
    -<*os400*>
    -<*win32*>
    -<*vms*>

; Configuration spécifique pour libssh2_esp
lib_ldf_mode = chain+
lib_compat_mode = strict

; Build flags for ESP-IDF + Arduino compatibility
build_flags =
    -DCONFIG_ARDUHAL_ESP_LOG
    -DCORE_DEBUG_LEVEL=3
    -DCONFIG_LWIP_SO_REUSE=1
    -I.pio/libdeps/esp32dev/libssh2_esp/libssh2/include
    -I.pio/libdeps/esp32dev/libssh2_esp/libssh2/src
    -I.pio/libdeps/esp32dev/libssh2_esp
    ; Configuration pour utiliser mbedTLS comme backend cryptographique
    -DLIBSSH2_MBEDTLS
    -DHAVE_LIBSSH2_H
    ; Désactiver zlib pour éviter la dépendance
    -DLIBSSH2_NO_ZLIB

; Use default partition table instead of huge_app.csv
; board_build.partitions = huge_app.csv
EOF

echo "✅ Configuration mise à jour dans $PLATFORMIO_INI"

# Nettoyer les répertoires problématiques si ils existent
LIBSSH2_PATH=".pio/libdeps/esp32dev/libssh2_esp"
if [ -d "$LIBSSH2_PATH" ]; then
    echo ""
    echo "🧹 Nettoyage des répertoires problématiques..."
    
    DIRS_TO_REMOVE=(
        "$LIBSSH2_PATH/libssh2/example"
        "$LIBSSH2_PATH/examples"
        "$LIBSSH2_PATH/libssh2/tests"
        "$LIBSSH2_PATH/libssh2/os400"
        "$LIBSSH2_PATH/libssh2/vms"
        "$LIBSSH2_PATH/libssh2/win32"
    )
    
    for dir in "${DIRS_TO_REMOVE[@]}"; do
        if [ -d "$dir" ]; then
            rm -rf "$dir"
            echo "   ✅ Supprimé: $dir"
        fi
    done
fi

echo ""
echo "🧪 Test de compilation..."
if command -v pio >/dev/null 2>&1; then
    if pio run --silent; then
        echo "✅ Compilation réussie !"
        echo ""
        echo "📊 Utilisation mémoire:"
        pio run 2>/dev/null | grep -E "(RAM|Flash):" || echo "   (Statistiques non disponibles)"
    else
        echo "❌ Échec de la compilation"
        echo ""
        echo "🔧 Actions recommandées:"
        echo "   1. Nettoyez le cache: pio run --target clean"
        echo "   2. Relancez la compilation: pio run"
        echo "   3. Vérifiez les erreurs de compilation"
    fi
else
    echo "⚠️  PlatformIO CLI non trouvé - impossible de tester la compilation"
    echo "   Vous pouvez tester manuellement avec: pio run"
fi

echo ""
echo "🎯 Script terminé !"
echo "📄 Configuration sauvegardée dans: $BACKUP_FILE"
echo "📄 Configuration mise à jour dans: $PLATFORMIO_INI"
echo ""
echo "💡 Si vous rencontrez encore des problèmes:"
echo "   1. Vérifiez que libssh2_esp est dans vos lib_deps"
echo "   2. Nettoyez le cache: pio run --target clean"
echo "   3. Relancez la compilation: pio run"
EOF

chmod +x fix_libssh2_simple.sh