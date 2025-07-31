# Documentation ESP-Reverse_Tunneling_Libssh2

Cette documentation couvre tous les aspects de la librairie ESP-Reverse_Tunneling_Libssh2.

## 📖 Guides principaux

### [SSH_KEYS_MEMORY.md](SSH_KEYS_MEMORY.md)
Guide complet pour l'authentification SSH par clés avec stockage en mémoire :
- Configuration des clés SSH
- Stockage sécurisé en LittleFS  
- Formats de clés supportés
- Exemples pratiques

### [HOST_KEY_VERIFICATION.md](HOST_KEY_VERIFICATION.md) 
Guide de sécurité pour la vérification des clés d'hôte :
- Protection contre les attaques Man-in-the-Middle
- Configuration des empreintes de serveur
- API de vérification
- Bonnes pratiques de sécurité
- Migration et dépannage

## 🔧 Configuration

### Authentification par mot de passe (simple)
```cpp
globalSSHConfig.setSSHServer("server.com", 22, "username", "password");
```

### Authentification par clé SSH (recommandée)
```cpp
globalSSHConfig.setSSHKeyAuthFromMemory(
    "server.com", 22, "username", 
    privateKeyData, publicKeyData, ""
);
```

### Configuration sécurisée complète
```cpp
// Authentification SSH
globalSSHConfig.setSSHKeyAuthFromMemory(
    "server.com", 22, "username",
    privateKeyData, publicKeyData, ""
);

// Vérification de l'identité du serveur
globalSSHConfig.setHostKeyVerification(
    "empreinte_sha256_du_serveur",
    "ssh-ed25519",
    true
);

// Configuration du tunnel
globalSSHConfig.setTunnelConfig(
    "0.0.0.0", 8080,    // Serveur distant (bind)
    "192.168.1.100", 80 // Cible locale (ESP32)
);
```

## 📊 Formats de clés supportés

| Format | Compatibilité | Recommandation |
|--------|---------------|----------------|
| OpenSSH moderne (`-----BEGIN OPENSSH PRIVATE KEY-----`) | ⚠️ Variable | Convertir en PKCS#8 |
| PKCS#8 (`-----BEGIN PRIVATE KEY-----`) | ✅ Excellente | **Recommandé** |
| PEM RSA (`-----BEGIN RSA PRIVATE KEY-----`) | ✅ Excellente | OK pour RSA |
| PEM EC (`-----BEGIN EC PRIVATE KEY-----`) | ✅ Bonne | OK pour ECDSA |

## 🔐 Algorithmes de clés supportés

| Algorithme | Support | Taille recommandée |
|------------|---------|-------------------|
| **Ed25519** | ✅ Excellent | 256 bits (fixe) |
| RSA | ✅ Excellent | 4096 bits |
| ECDSA P-256 | ✅ Bon | 256 bits |
| ECDSA P-384 | ✅ Bon | 384 bits |
| ECDSA P-521 | ✅ Bon | 521 bits |
| DSA | ⚠️ Déprécié | Non recommandé |

## 🛡️ Niveaux de sécurité

### Développement (niveau 1)
```cpp
globalSSHConfig.setSSHServer("server.com", 22, "user", "password");
// Pas de vérification d'hôte
```

### Production basique (niveau 2)  
```cpp
globalSSHConfig.setSSHKeyAuthFromMemory(/* clés SSH */);
// Authentification par clé mais pas de vérification d'hôte
```

### Production sécurisée (niveau 3) - **Recommandé**
```cpp
globalSSHConfig.setSSHKeyAuthFromMemory(/* clés SSH */);
globalSSHConfig.setHostKeyVerification(/* empreinte serveur */);
// Authentification par clé + vérification d'hôte
```

## 🚀 Démarrage rapide

### 1. Installation
```ini
# platformio.ini
lib_deps = 
    https://github.com/playmiel/ESP-Reverse_Tunneling_Libssh2.git
```

### 2. Code minimal
```cpp
#include "ESP-Reverse_Tunneling_Libssh2.h"

SSHTunnel tunnel;

void setup() {
    // Configuration WiFi
    WiFi.begin("SSID", "PASSWORD");
    
    // Configuration SSH
    globalSSHConfig.setSSHKeyAuthFromMemory(/* paramètres */);
    
    // Initialisation
    tunnel.init();
    tunnel.connectSSH();
}

void loop() {
    tunnel.loop();
}
```

### 3. Verification du statut
```cpp
if (tunnel.isConnected()) {
    Serial.println("Tunnel actif");
    Serial.printf("Canaux actifs: %d\n", tunnel.getActiveChannels());
    Serial.printf("Données reçues: %lu bytes\n", tunnel.getBytesReceived());
    Serial.printf("Données envoyées: %lu bytes\n", tunnel.getBytesSent());
}
```

## 🔍 Dépannage

### Problèmes courants

#### "Authentication failed"
- ✅ Vérifier le format des clés (préférer PKCS#8)
- ✅ Vérifier que la clé publique est dans `authorized_keys`
- ✅ Tester la connexion SSH manuelle depuis un PC

#### "Host key verification failed"  
- ✅ Obtenir la vraie empreinte du serveur
- ✅ Vérifier la configuration de l'empreinte
- ✅ S'assurer qu'il ne s'agit pas d'une attaque

#### "Connection timeout"
- ✅ Vérifier la connectivité réseau
- ✅ Vérifier que le port SSH est ouvert
- ✅ Tester avec un client SSH standard

### Logs utiles
```cpp
// Activer le debug détaillé
globalSSHConfig.setDebugConfig(true, 115200);

// Diagnostiquer les clés SSH
globalSSHConfig.diagnoseSSHKeys();
```

## 📈 Optimisations performances

### Mémoire
- Utiliser des clés Ed25519 (plus compactes)
- Ajuster `bufferSize` selon l'usage
- Limiter `maxChannels` selon les besoins

### Réseau
- Ajuster `keepAliveIntervalSec`
- Optimiser `channelTimeoutMs`
- Utiliser les optimisations réseau intégrées

### Configuration recommandée
```cpp
globalSSHConfig.setConnectionConfig(
    30,    // Keep-alive: 30s
    5000,  // Reconnect delay: 5s  
    10,    // Max reconnect attempts
    30     // Connection timeout: 30s
);

globalSSHConfig.setBufferConfig(
    8192,  // Buffer size: 8KB
    5,     // Max channels: 5
    300000 // Channel timeout: 5min
);
```

## 📞 Support

Pour des questions ou problèmes :
1. Consulter cette documentation
2. Vérifier les [examples/](../examples/) 
3. Activer les logs de debug
4. Ouvrir une issue sur GitHub

---

**Version de la documentation :** 1.0  
**Dernière mise à jour :** 2025-01-31
