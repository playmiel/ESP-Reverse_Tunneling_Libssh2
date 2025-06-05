# Optimisations du Tunnel SSH ESP32 pour Gros Transferts

## Problème identifié
Les "200 mismatch" lors de gros transferts de données sont causés par :
1. **Buffers trop petits** (1024 bytes)
2. **Gestion incomplète des écritures partielles**
3. **Absence de contrôle de flux**
4. **Timeouts trop courts**
5. **Configuration nginx non optimisée**

## Améliorations apportées

### 1. Augmentation de la taille des buffers
- **Avant** : `BUFFER_SIZE = 1024` bytes
- **Après** : `BUFFER_SIZE = 8192` bytes
- **Impact** : Réduit le nombre d'appels système et améliore les performances

### 2. Gestion des écritures partielles
```cpp
// Nouvelle logique qui garantit l'écriture complète des données
while (remaining > 0) {
  ssize_t written = send/libssh2_channel_write(...);
  if (written > 0) {
    totalWritten += written;
    remaining -= written;
  } else if (errno == EAGAIN) {
    delay(1); // Attendre que le buffer se libère
    continue;
  }
}
```

### 3. Timeout des canaux augmenté
- **Avant** : 5 minutes (300000 ms)
- **Après** : 30 minutes (1800000 ms)
- **Impact** : Évite la fermeture prématurée des connexions lors de gros transferts

### 4. Suivi amélioré de l'activité des canaux
- Mise à jour de `lastActivity` à chaque transfert de données
- Évite la fermeture de canaux actifs mais temporairement silencieux

## Configuration nginx optimisée

### Paramètres critiques
```nginx
# Tailles maximales
client_max_body_size 100M;
client_body_buffer_size 128k;

# Timeouts pour gros transferts
client_body_timeout 300s;
send_timeout 300s;
proxy_send_timeout 300s;
proxy_read_timeout 300s;

# Buffers proxy optimisés
proxy_buffer_size 64k;
proxy_buffers 8 64k;
proxy_busy_buffers_size 128k;

# Désactiver le buffering pour temps réel
proxy_buffering off;
proxy_request_buffering off;
```

## Instructions de déploiement

### 1. Mettre à jour le code ESP32
- Recompiler avec les nouveaux paramètres
- Vérifier que `BUFFER_SIZE = 8192`
- Surveiller l'utilisation mémoire

### 2. Configurer nginx
```bash
# Copier la configuration
sudo cp nginx_tunnel_config.conf /etc/nginx/sites-available/tunnel

# Activer le site
sudo ln -s /etc/nginx/sites-available/tunnel /etc/nginx/sites-enabled/

# Tester la configuration
sudo nginx -t

# Recharger nginx
sudo systemctl reload nginx
```

### 3. Surveillance et monitoring
```bash
# Logs nginx
tail -f /var/log/nginx/tunnel_error.log

# Statistiques ESP32 via Serial
# Surveiller : bytesReceived, bytesSent, activeChannels
```

## Paramètres de test recommandés

### Test de charge
1. **Petits fichiers** : 1-10 MB
2. **Fichiers moyens** : 50-100 MB  
3. **Gros fichiers** : 500 MB - 1 GB
4. **Transferts simultanés** : 2-3 connexions parallèles

### Métriques à surveiller
- Temps de transfert total
- Débit moyen (MB/s)
- Nombre de reconnexions SSH
- Erreurs nginx (codes 5xx)
- Utilisation mémoire ESP32

## Comparaison avec client PC

### Avantages client PC
- Buffers système plus grands
- TCP window scaling automatique
- Gestion mémoire dynamique
- Stack réseau optimisée

### Optimisations ESP32 pour compenser
- Buffers fixes mais optimisés (8KB)
- Contrôle de flux manuel
- Gestion explicite des écritures partielles
- Timeouts adaptés aux contraintes embarquées

## Dépannage

### Si les "200 mismatch" persistent
1. Vérifier les logs nginx : `proxy_upstream_timeout`
2. Augmenter encore les timeouts
3. Réduire `client_max_body_size` temporairement
4. Tester avec un seul canal à la fois

### Optimisations additionnelles possibles
- Compression gzip côté nginx
- Cache nginx pour fichiers statiques
- Limitation du débit (`limit_rate`)
- Pool de connexions SSH