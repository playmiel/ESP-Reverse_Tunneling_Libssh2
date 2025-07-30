# Corrections pour le problème de corruption de heap ESP32

## Problème identifié
Le problème de corruption de heap (`CORRUPT HEAP: Invalid data at 0x3f851c40`) est causé par:
1. Mauvaise gestion mémoire dans les buffers WiFi
2. Allocations non sécurisées dans le code SSH
3. Utilisation de `delay()` dans des contextes FreeRTOS
4. Fragmentation de la heap

## Corrections appliquées

### 1. Configuration PlatformIO (`platformio.ini`)
- Correction de la syntaxe (enlevé "apre" du début)
- Ajout d'optimisations mémoire WiFi:
  - `CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM=16`
  - `CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM=16`
  - Configuration PSRAM si disponible
  - Protection heap activée

### 2. Gestion mémoire sécurisée (`memory_fixes.h`)
- Macros `SAFE_FREE()` et `SAFE_DELETE_SEMAPHORE()`
- Fonction `safeMalloc()` avec vérifications
- Monitoring de l'état de la heap
- Détection de fragmentation

### 3. Corrections SSH Tunnel (`ssh_tunnel.cpp`)
- Remplacement de `malloc()` par `safeMalloc()`
- Remplacement de `delay()` par `vTaskDelay()`
- Correction des constantes non définies (MAX_CHANNELS, RECONNECT_DELAY_MS, etc.)
- Protection contre les NULL pointers
- Meilleure gestion des sémaphores

### 4. Monitoring amélioré (`main.cpp`)
- Vérification de l'état heap avant logging
- Réduction des logs en cas de mémoire faible
- Alertes automatiques si heap critique
- Détection de fragmentation

## Recommandations d'utilisation

### Configuration recommandée:
```cpp
globalSSHConfig.setBufferConfig(
    4096,    // Buffer plus petit (au lieu de 8192)
    3,       // Moins de canaux (au lieu de 10)
    900000   // Timeout plus court (15 min au lieu de 30)
);
```

### Surveillance:
- Surveiller les logs `[HEAP_WARNING]`
- Redémarrer si heap < 30KB
- Éviter les transferts de gros fichiers prolongés

### En cas de problème persistant:
1. Réduire la taille des buffers à 2048
2. Limiter à 1-2 canaux maximum  
3. Ajouter des pauses avec `vTaskDelay()` dans les boucles
4. Considérer l'utilisation de PSRAM si disponible sur votre ESP32

## Test des corrections
Compiler avec: `pio run`
Monitor: `pio device monitor`

Les logs doivent maintenant afficher:
- `[MALLOC_DEBUG]` pour les allocations
- `[HEAP_WARNING]` si problème détecté
- `Free Heap: X bytes (min: Y, largest: Z)` pour le monitoring
