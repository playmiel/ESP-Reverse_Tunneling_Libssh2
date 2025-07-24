#!/bin/bash

# Script générique pour corriger automatiquement la configuration libssh2_esp
# Usage: ./fix_libssh2_config.sh [chemin_vers_platformio.ini]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORMIO_INI="${1:-platformio.ini}"

echo "🔧 Script de correction automatique pour libssh2_esp"
echo "=================================================="
echo "📁 Répertoire de travail: $(pwd)"
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

# Fonction pour ajouter une configuration si elle n'existe pas
add_config_if_missing() {
    local config_line="$1"
    local section="$2"
    
    if ! grep -q "$config_line" "$PLATFORMIO_INI"; then
        echo "   ➕ Ajout: $config_line"
        
        # Si c'est un build_flags, l'ajouter dans la section appropriée
        if [[ "$config_line" == *"build_flags"* ]]; then
            # Chercher si build_flags existe déjà
            if grep -q "^build_flags" "$PLATFORMIO_INI"; then
                # Ajouter à la fin des build_flags existants
                sed -i "/^build_flags/,/^[[:space:]]*$/{
                    /^[[:space:]]*-/ {
                        a\\
    $config_line
                        b
                    }
                    /^build_flags/ {
                        a\\
    $config_line
                    }
                }" "$PLATFORMIO_INI"
            else
                # Ajouter build_flags après monitor_speed ou à la fin de la section
                if grep -q "monitor_speed" "$PLATFORMIO_INI"; then
                    sed -i "/monitor_speed/a\\
\\
; Build flags for libssh2_esp compatibility\\
build_flags =\\
    $config_line" "$PLATFORMIO_INI"
                else
                    # Ajouter à la fin de la section [env:...]
                    sed -i "/^\[env:/,/^\[/{
                        /^\[env:/ {
                            a\\
\\
; Build flags for libssh2_esp compatibility\\
build_flags =\\
    $config_line
                        }
                    }" "$PLATFORMIO_INI"
                fi
            fi
        else
            # Pour les autres configurations, les ajouter après lib_deps
            if grep -q "lib_deps" "$PLATFORMIO_INI"; then
                sed -i "/lib_deps/,/^[[:space:]]*$/{
                    /^[[:space:]]*[^[:space:]]/ {
                        a\\
$config_line
                        b
                    }
                    /lib_deps/ {
                        /=/ {
                            a\\
$config_line
                        }
                    }
                }" "$PLATFORMIO_INI"
            fi
        fi
    else
        echo "   ✅ Déjà présent: $config_line"
    fi
}

echo "🔧 Application des corrections..."

# Ajouter les configurations nécessaires
add_config_if_missing "; Configuration pour libssh2_esp - exclure les exemples"
add_config_if_missing "lib_ignore = 
    libssh2_esp/libssh2/example
    libssh2_esp/libssh2/tests
    libssh2_esp/libssh2/docs"

add_config_if_missing "; Filtres de source pour éviter la compilation des exemples"
add_config_if_missing "build_src_filter = 
    +<*>
    -<.git/>
    -<.svn/>
    -<example/>
    -<examples/>
    -<test/>
    -<tests/>
    -<docs/>"

add_config_if_missing "; Configuration spécifique pour libssh2_esp"
add_config_if_missing "lib_ldf_mode = chain+"
add_config_if_missing "lib_compat_mode = strict"

# Ajouter les build flags
add_config_if_missing "-DCONFIG_ARDUHAL_ESP_LOG" "build_flags"
add_config_if_missing "-DCORE_DEBUG_LEVEL=3" "build_flags"
add_config_if_missing "-DCONFIG_LWIP_SO_REUSE=1" "build_flags"
add_config_if_missing "-I.pio/libdeps/esp32dev/libssh2_esp/libssh2/include" "build_flags"
add_config_if_missing "-I.pio/libdeps/esp32dev/libssh2_esp/libssh2/src" "build_flags"
add_config_if_missing "-I.pio/libdeps/esp32dev/libssh2_esp" "build_flags"
add_config_if_missing "; Configuration pour utiliser mbedTLS comme backend cryptographique" "build_flags"
add_config_if_missing "-DLIBSSH2_MBEDTLS" "build_flags"
add_config_if_missing "-DHAVE_LIBSSH2_H" "build_flags"
add_config_if_missing "; Désactiver zlib pour éviter la dépendance" "build_flags"
add_config_if_missing "-DLIBSSH2_NO_ZLIB" "build_flags"

echo ""
echo "📝 Configuration mise à jour dans $PLATFORMIO_INI"

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