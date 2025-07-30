# Utilisation des clés SSH avec libssh2_userauth_publickey_frommemory

Ce guide explique comment utiliser l'authentification SSH par clé publique avec les clés stockées en mémoire au lieu de fichiers, ce qui est plus fiable avec LittleFS sur ESP32.

## Avantages de l'authentification par clé en mémoire

- **Compatibilité LittleFS** : Évite les problèmes de lecture de fichiers avec LittleFS
- **Performance** : Pas d'accès disque pendant l'authentification
- **Sécurité** : Les clés peuvent être chargées une seule fois au démarrage
- **Fiabilité** : Évite les erreurs de chemin de fichier

## Méthodes d'utilisation

### 1. Configuration avec clés directement en mémoire

```cpp
String privateKey = R"(-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn
... (votre clé privée complète ici)
-----END OPENSSH PRIVATE KEY-----)";

String publicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... user@host";

globalSSHConfig.setSSHKeyAuthFromMemory(
  "your-remote-server.com",
  22,
  "your_username",
  privateKey,
  publicKey,
  ""  // Passphrase optionnelle
);
```

### 2. Chargement automatique depuis LittleFS

```cpp
// Cette méthode charge automatiquement les clés en mémoire
globalSSHConfig.setSSHKeyAuth(
  "your-remote-server.com",
  22,
  "your_username",
  "/ssh_key",       // Chemin vers la clé privée dans LittleFS
  ""                // Passphrase optionnelle
);
```

### 3. Chargement manuel depuis LittleFS

```cpp
// Initialiser LittleFS
if (!LittleFS.begin(true)) {
  LOG_E("CONFIG", "Failed to initialize LittleFS");
  return;
}

// Charger les clés en mémoire
if (globalSSHConfig.loadSSHKeysFromLittleFS("/ssh_key")) {
  LOG_I("CONFIG", "SSH keys loaded successfully");
} else {
  LOG_E("CONFIG", "Failed to load SSH keys");
}
```

## Préparation des clés SSH

### Génération des clés

```bash
# Générer une paire de clés SSH
ssh-keygen -t rsa -b 2048 -f ssh_key -N ""

# Cela créera :
# - ssh_key (clé privée)
# - ssh_key.pub (clé publique)
```

### Upload vers LittleFS

1. **Via l'outil ESP32 Sketch Data Upload** :
   - Placez vos clés dans le dossier `data/` de votre projet
   - Utilisez l'outil "ESP32 Sketch Data Upload" dans Arduino IDE

2. **Programmatiquement** :
   ```cpp
   File privateKeyFile = LittleFS.open("/ssh_key", "w");
   privateKeyFile.print(privateKeyString);
   privateKeyFile.close();
   
   File publicKeyFile = LittleFS.open("/ssh_key.pub", "w");
   publicKeyFile.print(publicKeyString);
   publicKeyFile.close();
   ```

## Exemple complet

```cpp
#include <WiFi.h>
#include <LittleFS.h>
#include "ESP-Reverse_Tunneling_Libssh2.h"

void setup() {
  Serial.begin(115200);
  
  // Initialiser LittleFS
  if (!LittleFS.begin(true)) {
    LOG_E("MAIN", "Failed to initialize LittleFS");
    return;
  }
  
  // Configuration WiFi
  WiFi.begin("YOUR_SSID", "YOUR_PASSWORD");
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
  }
  
  // Configuration SSH avec clés depuis LittleFS
  globalSSHConfig.setSSHKeyAuth(
    "your-server.com",
    22,
    "your_username",
    "/ssh_key",
    ""  // Pas de passphrase
  );
  
  // Configuration du tunnel
  globalSSHConfig.setTunnelConfig("0.0.0.0", 8080, "192.168.1.100", 80);
  
  // Initialiser et connecter le tunnel
  SSHTunnel tunnel;
  if (tunnel.init() && tunnel.connectSSH()) {
    LOG_I("MAIN", "SSH tunnel established successfully");
  }
}
```

## Dépannage

### Problème : "SSH keys not available in memory"
- Vérifiez que LittleFS est initialisé
- Vérifiez que les fichiers de clés existent dans LittleFS
- Vérifiez les permissions de lecture des fichiers

### Problème : "Authentication by public key from memory failed"
- Vérifiez le format des clés (OpenSSH ou PEM)
- Vérifiez que la clé publique correspond à la clé privée
- Vérifiez que la passphrase est correcte si utilisée

### Problème : Format de clé non supporté
- libssh2 supporte les formats OpenSSH et PEM
- Convertir au besoin : `ssh-keygen -p -m PEM -f ssh_key`

## Notes de sécurité

1. **Ne jamais** inclure de vraies clés privées dans le code source
2. Utiliser des clés dédiées pour l'ESP32
3. Stocker les clés de manière sécurisée (chiffrement, accès restreint)
4. Considérer l'utilisation de certificats temporaires si possible

## Compatibilité

- ✅ OpenSSH private key format
- ✅ PEM private key format  
- ✅ RSA keys
- ✅ ED25519 keys (si supporté par libssh2)
- ✅ Clés avec et sans passphrase
