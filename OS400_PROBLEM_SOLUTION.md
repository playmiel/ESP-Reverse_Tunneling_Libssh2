# Solution au problème de compilation OS/400 avec libssh2_esp

## Problème
Lors de la compilation pour ESP32, PlatformIO essaie de compiler les fichiers OS/400 de libssh2, causant des erreurs comme :
```
.pio/libdeps/esp32dev/libssh2_esp/libssh2/os400/ccsid.c:46:10: fatal error: qtqiconv.h: No such file or directory
.pio/libdeps/esp32dev/libssh2_esp/libssh2/os400/os400sys.c:58:10: fatal error: qadrt.h: No such file or directory
```

## Cause
La bibliothèque libssh2 contient des fichiers spécifiques à différentes plateformes (OS/400, Windows, VMS, etc.). PlatformIO, par défaut, essaie de compiler tous les fichiers `.c` trouvés dans les dépendances, y compris ceux qui ne sont pas destinés à l'ESP32.

## Solution mise en place

### 1. Configuration renforcée dans platformio.ini
```ini
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
    -<*/os400/>
    -<*/win32/>
    -<*/vms/>
    -<libssh2/os400/>
    -<libssh2/win32/>
    -<libssh2/vms/>
    -<**/os400/>
    -<**/win32/>
    -<**/vms/>
```

### 2. Script de correction amélioré
Le script `fix_libssh2_esp.sh` a été amélioré pour supprimer physiquement tous les fichiers OS/400 :
```bash
echo "   - Suppression de tous les fichiers OS/400 restants..."
find "$LIBSSH2_PATH" -name "*os400*" -type f -delete 2>/dev/null
find "$LIBSSH2_PATH" -name "*qtqiconv*" -type f -delete 2>/dev/null
find "$LIBSSH2_PATH" -name "*qadrt*" -type f -delete 2>/dev/null
find "$LIBSSH2_PATH" -name "ccsid.c" -delete 2>/dev/null
find "$LIBSSH2_PATH" -name "os400sys.c" -delete 2>/dev/null
```

### 3. Workflow GitHub Actions amélioré
Le workflow a été modifié pour :
1. D'abord télécharger les dépendances : `pio pkg install`
2. Ensuite appliquer le script de correction : `./fix_libssh2_esp.sh`
3. Enfin compiler : `pio run -e esp32dev`
4. Vérifier qu'aucun fichier OS/400 n'a été compilé

## Utilisation
1. Exécuter le script de correction après avoir téléchargé les dépendances :
   ```bash
   cd examples
   pio pkg install
   chmod +x fix_libssh2_esp.sh
   ./fix_libssh2_esp.sh
   ```

2. La compilation devrait maintenant fonctionner sans erreur :
   ```bash
   pio run -e esp32dev
   ```

## Pourquoi ce problème se produit-il ?
- libssh2 est une bibliothèque multiplateforme qui inclut du code pour IBM i (OS/400)
- PlatformIO compile tous les fichiers `.c` qu'il trouve dans les dépendances
- Les filtres de build par défaut ne sont pas assez précis pour exclure ces fichiers
- La solution combine exclusion par configuration ET suppression physique des fichiers

Cette solution garantit que seuls les fichiers pertinents pour ESP32 sont compilés.
