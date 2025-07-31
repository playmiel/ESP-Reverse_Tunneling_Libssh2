# Vérification des Clés d'Hôte (Known Hosts)

## Introduction

La vérification des clés d'hôte est un mécanisme de sécurité crucial qui protège contre les attaques **Man-in-the-Middle (MITM)**. Cette fonctionnalité vérifie l'identité du serveur SSH en comparant son empreinte cryptographique avec une valeur attendue.

## Pourquoi c'est important

### Sans vérification des clés d'hôte :
```
Internet → [Attaquant] → [Votre ESP32] → [Vrai serveur]
           ↑
    Se fait passer pour votre serveur
    Peut intercepter/modifier tout le trafic
```

### Avec vérification :
- ✅ **Détection d'attaques MITM**
- ✅ **Vérification de l'identité du serveur**
- ✅ **Protection des données sensibles**
- ✅ **Conformité aux bonnes pratiques de sécurité**

## Configuration

### 1. Obtenir l'empreinte du serveur

#### Sur votre serveur Linux :
```bash
# Obtenir l'empreinte SHA256 de la clé Ed25519
ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub -E sha256

# Ou depuis un client
ssh-keyscan -t ed25519 votre-serveur.com | ssh-keygen -lf - -E sha256
```

#### Exemple de sortie :
```
256 SHA256:abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56 root@server (ED25519)
```

### 2. Configuration dans votre code ESP32

#### Méthode 1 : Configuration complète
```cpp
#include "ESP-Reverse_Tunneling_Libssh2.h"

void setup() {
    // Configuration SSH normale
    globalSSHConfig.setSSHKeyAuthFromMemory(
        "votre-serveur.com",
        22,
        "username",
        privateKey,
        publicKey,
        ""  // Pas de passphrase
    );

    // Activer la vérification avec empreinte attendue
    globalSSHConfig.setHostKeyVerification(
        "abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56", // Empreinte SHA256
        "ssh-ed25519",  // Type de clé attendu
        true           // Activer la vérification
    );
}
```

#### Méthode 2 : Configuration étape par étape
```cpp
// D'abord configurer SSH normalement
globalSSHConfig.setSSHKeyAuthFromMemory(/* paramètres SSH */);

// Puis configurer la vérification
globalSSHConfig.setHostKeyVerification(true);
globalSSHConfig.setExpectedHostKey(
    "abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56",
    "ssh-ed25519"
);
```

#### Méthode 3 : Mode découverte (première connexion)
```cpp
// Désactiver la vérification pour découvrir l'empreinte
globalSSHConfig.setHostKeyVerification(false);

// Dans les logs, vous verrez :
// [INFO] Store this fingerprint in your configuration: abcd1234...
// Utilisez ensuite cette empreinte pour activer la vérification
```

## API de Configuration

### Méthodes disponibles

```cpp
class SSHConfiguration {
public:
    // Activer/désactiver la vérification
    void setHostKeyVerification(bool enable);
    
    // Configurer l'empreinte attendue
    void setExpectedHostKey(const String& fingerprint, const String& keyType = "");
    
    // Configuration complète en une fois
    void setHostKeyVerification(const String& fingerprint, const String& keyType = "", bool enable = true);
};
```

### Paramètres

| Paramètre | Type | Description |
|-----------|------|-------------|
| `fingerprint` | String | Empreinte SHA256 (64 caractères hex) |
| `keyType` | String | Type de clé : "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-*" |
| `enable` | bool | Activer/désactiver la vérification |

## Types de clés supportés

| Type | Constante libssh2 | Chaîne de configuration |
|------|------------------|------------------------|
| RSA | `LIBSSH2_HOSTKEY_TYPE_RSA` | `"ssh-rsa"` |
| DSA | `LIBSSH2_HOSTKEY_TYPE_DSS` | `"ssh-dss"` |
| ECDSA P-256 | `LIBSSH2_HOSTKEY_TYPE_ECDSA_256` | `"ecdsa-sha2-nistp256"` |
| ECDSA P-384 | `LIBSSH2_HOSTKEY_TYPE_ECDSA_384` | `"ecdsa-sha2-nistp384"` |
| ECDSA P-521 | `LIBSSH2_HOSTKEY_TYPE_ECDSA_521` | `"ecdsa-sha2-nistp521"` |
| Ed25519 | `LIBSSH2_HOSTKEY_TYPE_ED25519` | `"ssh-ed25519"` |

## Logs et Debug

### Logs normaux (vérification réussie)
```
[INFO] Server host key: ssh-ed25519
[INFO] Server fingerprint (SHA256): abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56
[INFO] Host key verification successful
```

### Logs d'erreur (empreinte incorrecte)
```
[ERROR] HOST KEY VERIFICATION FAILED!
[ERROR] This could indicate a Man-in-the-Middle attack!
[ERROR] Expected: abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56
[ERROR] Got:      xyz9876fedcba5432109876543210abcdef1234567890abcdef12
[ERROR] Key type: ssh-ed25519
```

### Mode découverte
```
[WARN] Host key verification disabled - connection accepted without verification
[INFO] Server host key: ssh-ed25519
[INFO] Server fingerprint (SHA256): abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56
[WARN] No expected fingerprint configured - accepting and storing current fingerprint
[INFO] Store this fingerprint in your configuration: abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz56
```

## Exemples d'utilisation

### Exemple 1 : Configuration de production
```cpp
void configureSecureSSH() {
    // Clés SSH
    String privateKey = R"(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBxK5c3j7kJ9QZ8fG3mVlM2fk8WdlMJq5018faI4C4eA
-----END PRIVATE KEY-----)";
    
    String publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAebBChSTfMPbiXfphT6KUzZ+TxZ2UwmrnTXx9ojgLh4 esp32-device";
    
    // Configuration complète sécurisée
    globalSSHConfig.setSSHKeyAuthFromMemory(
        "production-server.com",
        22,
        "tunnel-user",
        privateKey,
        publicKey,
        ""
    );
    
    // Vérification obligatoire en production
    globalSSHConfig.setHostKeyVerification(
        "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        "ssh-ed25519",
        true
    );
}
```

### Exemple 2 : Configuration de développement
```cpp
void configureDevSSH() {
    // Configuration SSH normale
    globalSSHConfig.setSSHKeyAuthFromMemory(/* paramètres */);
    
    // Mode découverte pour obtenir l'empreinte
    globalSSHConfig.setHostKeyVerification(false);
    
    // TODO: Remplacer par la vraie empreinte une fois obtenue
    // globalSSHConfig.setHostKeyVerification("EMPREINTE_ICI", "ssh-ed25519", true);
}
```

### Exemple 3 : Configuration flexible
```cpp
void configureFlexibleSSH() {
    // Configuration SSH
    globalSSHConfig.setSSHKeyAuthFromMemory(/* paramètres */);
    
    #ifdef PRODUCTION
        // Vérification stricte en production
        globalSSHConfig.setHostKeyVerification(
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
            "ssh-ed25519",
            true
        );
    #else
        // Mode permissif en développement
        globalSSHConfig.setHostKeyVerification(false);
        LOG_W("SSH", "Host key verification disabled in development mode");
    #endif
}
```

## Sécurité et bonnes pratiques

### ✅ Recommandations

1. **Toujours activer en production**
   ```cpp
   globalSSHConfig.setHostKeyVerification(true);
   ```

2. **Utiliser des empreintes complètes**
   - SHA256 recommandé (64 caractères hex)
   - Éviter SHA1 (déprécié)

3. **Spécifier le type de clé**
   ```cpp
   globalSSHConfig.setExpectedHostKey("empreinte", "ssh-ed25519");
   ```

4. **Surveiller les logs**
   - Alertes automatiques sur échec de vérification
   - Monitoring des changements d'empreinte

### ❌ À éviter

1. **Ne jamais désactiver en production**
   ```cpp
   // DANGEREUX en production !
   globalSSHConfig.setHostKeyVerification(false);
   ```

2. **Ne pas ignorer les erreurs de vérification**
   - Un échec peut indiquer une attaque
   - Investiguer tout changement d'empreinte

3. **Ne pas utiliser d'empreintes partielles**
   - Toujours utiliser l'empreinte complète
   - Vérifier la casse et les caractères

## Dépannage

### Problème : "Host key verification failed"

**Causes possibles :**
- Serveur reconfiguré avec de nouvelles clés
- Attaque Man-in-the-Middle
- Erreur de configuration (mauvaise empreinte)

**Solutions :**
1. Vérifier l'empreinte sur le serveur
2. Comparer avec l'empreinte configurée
3. Mettre à jour si le serveur a changé légitimement

### Problème : "Failed to get host key from server"

**Causes possibles :**
- Problème de connexion réseau
- Serveur SSH non disponible
- Version libssh2 incompatible

**Solutions :**
1. Vérifier la connectivité réseau
2. Tester la connexion SSH manuelle
3. Vérifier les logs du serveur

### Problème : Type de clé non reconnu

**Solutions :**
1. Utiliser un type de clé supporté
2. Mettre à jour libssh2 si nécessaire
3. Configurer le serveur avec un algorithme supporté

## Structure de configuration

### Dans ssh_config.h
```cpp
struct SSHServerConfig {
    String host;
    int port;
    String username;
    String password;
    bool useSSHKey;
    String privateKeyData;
    String publicKeyData;
    
    // Configuration known hosts
    bool verifyHostKey;                    // Activer/désactiver
    String expectedHostKeyFingerprint;    // Empreinte SHA256
    String hostKeyType;                   // Type de clé attendu
};
```

### Valeurs par défaut
```cpp
SSHServerConfig() : 
    // ... autres paramètres ...
    verifyHostKey(false),                  // Désactivé par défaut
    expectedHostKeyFingerprint(""),       // Aucune empreinte
    hostKeyType("") {}                    // Tous types acceptés
```

## Migration depuis une version sans vérification

### Étape 1 : Mise à jour du code
```cpp
// Ancien code (sans vérification)
globalSSHConfig.setSSHKeyAuthFromMemory(host, port, user, privKey, pubKey, "");

// Nouveau code (avec découverte)
globalSSHConfig.setSSHKeyAuthFromMemory(host, port, user, privKey, pubKey, "");
globalSSHConfig.setHostKeyVerification(false); // Mode découverte temporaire
```

### Étape 2 : Obtenir l'empreinte
1. Compiler et flasher avec le mode découverte
2. Noter l'empreinte dans les logs
3. Sauvegarder l'empreinte en lieu sûr

### Étape 3 : Activer la vérification
```cpp
// Configuration finale sécurisée
globalSSHConfig.setSSHKeyAuthFromMemory(host, port, user, privKey, pubKey, "");
globalSSHConfig.setHostKeyVerification(
    "empreinte_obtenue_etape_2",
    "ssh-ed25519", 
    true
);
```

## Exemple complet

```cpp
#include "ESP-Reverse_Tunneling_Libssh2.h"

// Configuration sécurisée complète
void setupSecureSSHTunnel() {
    // Clés SSH au format PKCS#8 (recommandé)
    String privateKey = R"(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBxK5c3j7kJ9QZ8fG3mVlM2fk8WdlMJq5018faI4C4eA
-----END PRIVATE KEY-----)";
    
    String publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAebBChSTfMPbiXfphT6KUzZ+TxZ2UwmrnTXx9ojgLh4 esp32-tunnel";
    
    // Configuration SSH avec authentification par clé
    globalSSHConfig.setSSHKeyAuthFromMemory(
        "tunnel.example.com",   // Serveur SSH
        22,                     // Port SSH
        "tunnel-user",          // Utilisateur
        privateKey,             // Clé privée
        publicKey,              // Clé publique
        ""                      // Pas de passphrase
    );
    
    // Configuration du tunnel reverse
    globalSSHConfig.setTunnelConfig(
        "0.0.0.0",             // Bind sur toutes les interfaces du serveur
        8080,                  // Port distant (serveur)
        "192.168.1.100",       // IP locale (ESP32)
        80                     // Port local (serveur web ESP32)
    );
    
    // Configuration sécurisée avec vérification des clés d'hôte
    globalSSHConfig.setHostKeyVerification(
        "a1b2c3d4e5f67890123456789012345678901234567890abcdef1234567890ab",  // Empreinte SHA256
        "ssh-ed25519",                                                      // Type de clé
        true                                                               // Activer
    );
    
    // Configuration des paramètres de connexion
    globalSSHConfig.setConnectionConfig(
        30,    // Keep-alive: 30 secondes
        5000,  // Délai de reconnexion: 5 secondes
        10,    // Max tentatives de reconnexion
        30     // Timeout de connexion: 30 secondes
    );
}

void setup() {
    Serial.begin(115200);
    
    // Configuration WiFi
    WiFi.begin("SSID", "PASSWORD");
    while (WiFi.status() != WL_CONNECTED) {
        delay(1000);
        Serial.println("Connecting to WiFi...");
    }
    
    // Configuration sécurisée du tunnel SSH
    setupSecureSSHTunnel();
    
    // Initialisation du tunnel
    if (!tunnel.init()) {
        Serial.println("Failed to initialize SSH tunnel");
        return;
    }
    
    Serial.println("SSH tunnel initialized with host key verification enabled");
}

void loop() {
    tunnel.loop();
    delay(10);
}
```

Cette documentation complète couvre tous les aspects de la vérification des clés d'hôte dans votre librairie ESP-Reverse_Tunneling_Libssh2.
