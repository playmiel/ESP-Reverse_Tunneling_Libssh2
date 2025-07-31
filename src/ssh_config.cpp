#include "ssh_config.h"
#include "logger.h"
#include "LittleFS.h"

// Instance globale de configuration
SSHConfiguration globalSSHConfig;

SSHConfiguration::SSHConfiguration() {
    // Créer le sémaphore pour la protection thread-safe
    configMutex = xSemaphoreCreateMutex();
    if (configMutex == NULL) {
        LOG_E("CONFIG", "Failed to create configuration mutex");
    }
}

SSHConfiguration::~SSHConfiguration() {
    if (configMutex != NULL) {
        vSemaphoreDelete(configMutex);
    }
}

void SSHConfiguration::setSSHServer(const String& host, int port, const String& username, const String& password) {
    if (lockConfig()) {
        sshConfig.host = host;
        sshConfig.port = port;
        sshConfig.username = username;
        sshConfig.password = password;
        sshConfig.useSSHKey = false;
        unlockConfig();
        
        LOGF_I("CONFIG", "SSH server configured: %s:%d (user: %s)", host.c_str(), port, username.c_str());
    }
}

void SSHConfiguration::setSSHKeyAuth(const String& host, int port, const String& username, const String& privateKeyPath, const String& passphrase) {
    if (lockConfig()) {
        sshConfig.host = host;
        sshConfig.port = port;
        sshConfig.username = username;
        sshConfig.privateKeyPath = privateKeyPath;
        sshConfig.password = passphrase; // Utilisé comme passphrase pour la clé
        sshConfig.useSSHKey = true;
        
        // Essayer de charger les clés depuis LittleFS
        if (!loadSSHKeysFromLittleFS(privateKeyPath)) {
            LOGF_W("CONFIG", "Could not load SSH keys from LittleFS: %s", privateKeyPath.c_str());
        }
        
        unlockConfig();
        
        LOGF_I("CONFIG", "SSH key auth configured: %s:%d (user: %s, key: %s)", 
               host.c_str(), port, username.c_str(), privateKeyPath.c_str());
    }
}

void SSHConfiguration::setSSHKeyAuthFromMemory(const String& host, int port, const String& username, const String& privateKeyData, const String& publicKeyData, const String& passphrase) {
    if (lockConfig()) {
        sshConfig.host = host;
        sshConfig.port = port;
        sshConfig.username = username;
        sshConfig.privateKeyData = privateKeyData;
        sshConfig.publicKeyData = publicKeyData;
        sshConfig.password = passphrase; // Utilisé comme passphrase pour la clé
        sshConfig.useSSHKey = true;
        unlockConfig();
        
        LOGF_I("CONFIG", "SSH key auth from memory configured: %s:%d (user: %s)", 
               host.c_str(), port, username.c_str());
    }
}

bool SSHConfiguration::loadSSHKeysFromLittleFS(const String& privateKeyPath) {
    // Charger la clé privée
    File privateKeyFile = LittleFS.open(privateKeyPath, "r");
    if (!privateKeyFile) {
        LOGF_E("CONFIG", "Cannot open private key file: %s", privateKeyPath.c_str());
        return false;
    }
    
    sshConfig.privateKeyData = privateKeyFile.readString();
    privateKeyFile.close();
    
    if (sshConfig.privateKeyData.length() == 0) {
        LOG_E("CONFIG", "Private key file is empty");
        return false;
    }
    
    // Charger la clé publique (généralement .pub)
    String publicKeyPath = privateKeyPath + ".pub";
    File publicKeyFile = LittleFS.open(publicKeyPath, "r");
    if (!publicKeyFile) {
        LOGF_E("CONFIG", "Cannot open public key file: %s", publicKeyPath.c_str());
        return false;
    }
    
    sshConfig.publicKeyData = publicKeyFile.readString();
    publicKeyFile.close();
    
    if (sshConfig.publicKeyData.length() == 0) {
        LOG_E("CONFIG", "Public key file is empty");
        return false;
    }
    
    LOGF_I("CONFIG", "SSH keys loaded from LittleFS (private: %d bytes, public: %d bytes)", 
           sshConfig.privateKeyData.length(), sshConfig.publicKeyData.length());
    
    return true;
}

bool SSHConfiguration::loadSSHKeysFromFile(const String& privateKeyPath) {
    // Cette méthode peut être utilisée pour d'autres systèmes de fichiers
    // Pour l'instant, on utilise LittleFS
    return loadSSHKeysFromLittleFS(privateKeyPath);
}

void SSHConfiguration::setSSHKeysInMemory(const String& privateKeyData, const String& publicKeyData) {
    if (lockConfig()) {
        // Nettoyer et valider les clés
        String cleanPrivateKey = privateKeyData;
        String cleanPublicKey = publicKeyData;
        
        // S'assurer que les clés se terminent par un retour à la ligne
        if (!cleanPrivateKey.endsWith("\n")) {
            cleanPrivateKey += "\n";
        }
        if (!cleanPublicKey.endsWith("\n")) {
            cleanPublicKey += "\n";
        }
        
        // Remplacer les retours à la ligne Windows par Unix si nécessaire
        cleanPrivateKey.replace("\r\n", "\n");
        cleanPublicKey.replace("\r\n", "\n");
        
        sshConfig.privateKeyData = cleanPrivateKey;
        sshConfig.publicKeyData = cleanPublicKey;
        unlockConfig();
        
        LOGF_I("CONFIG", "SSH keys set in memory (private: %d bytes, public: %d bytes)", 
               cleanPrivateKey.length(), cleanPublicKey.length());
        
        // Validation basique des clés
        if (cleanPrivateKey.indexOf("-----BEGIN") == -1 || cleanPrivateKey.indexOf("-----END") == -1) {
            LOG_W("CONFIG", "Private key might not be properly formatted");
        }
        if (cleanPublicKey.indexOf("ssh-") != 0 && cleanPublicKey.indexOf("ecdsa-") != 0) {
            LOG_W("CONFIG", "Public key might not be properly formatted");
        }
    }
}

bool SSHConfiguration::validateSSHKeys() const {
    if (!lockConfig()) {
        return false;
    }
    
    bool valid = true;
    
    if (sshConfig.privateKeyData.length() == 0) {
        LOG_E("CONFIG", "Private key is empty");
        valid = false;
    } else {
        if (sshConfig.privateKeyData.indexOf("-----BEGIN") == -1) {
            LOG_E("CONFIG", "Private key missing BEGIN marker");
            valid = false;
        }
        if (sshConfig.privateKeyData.indexOf("-----END") == -1) {
            LOG_E("CONFIG", "Private key missing END marker");
            valid = false;
        }
    }
    
    if (sshConfig.publicKeyData.length() == 0) {
        LOG_E("CONFIG", "Public key is empty");
        valid = false;
    } else {
        if (sshConfig.publicKeyData.indexOf("ssh-") != 0 && 
            sshConfig.publicKeyData.indexOf("ecdsa-") != 0) {
            LOG_E("CONFIG", "Public key doesn't start with proper algorithm identifier");
            valid = false;
        }
    }
    
    unlockConfig();
    return valid;
}

void SSHConfiguration::diagnoseSSHKeys() const {
    if (!lockConfig()) {
        return;
    }
    
    LOG_I("CONFIG", "=== SSH Keys Diagnosis ===");
    
    // Analyser la clé privée
    if (sshConfig.privateKeyData.length() > 0) {
        LOGF_I("CONFIG", "Private key length: %d bytes", sshConfig.privateKeyData.length());
        
        if (sshConfig.privateKeyData.indexOf("-----BEGIN OPENSSH PRIVATE KEY-----") != -1) {
            LOG_I("CONFIG", "Private key format: OpenSSH modern format");
            LOG_W("CONFIG", "Note: OpenSSH format may not be fully supported by all libssh2 versions");
        } else if (sshConfig.privateKeyData.indexOf("-----BEGIN RSA PRIVATE KEY-----") != -1) {
            LOG_I("CONFIG", "Private key format: RSA PEM format");
        } else if (sshConfig.privateKeyData.indexOf("-----BEGIN EC PRIVATE KEY-----") != -1) {
            LOG_I("CONFIG", "Private key format: EC PEM format");
        } else if (sshConfig.privateKeyData.indexOf("-----BEGIN PRIVATE KEY-----") != -1) {
            LOG_I("CONFIG", "Private key format: PKCS#8 PEM format");
        } else {
            LOG_W("CONFIG", "Private key format: Unknown or invalid");
        }
        
        // Vérifier les fins de ligne
        if (sshConfig.privateKeyData.indexOf("\r\n") != -1) {
            LOG_W("CONFIG", "Private key contains Windows line endings (CRLF)");
        } else if (sshConfig.privateKeyData.indexOf("\n") != -1) {
            LOG_I("CONFIG", "Private key uses Unix line endings (LF)");
        } else {
            LOG_W("CONFIG", "Private key might not have proper line endings");
        }
    }
    
    // Analyser la clé publique
    if (sshConfig.publicKeyData.length() > 0) {
        LOGF_I("CONFIG", "Public key length: %d bytes", sshConfig.publicKeyData.length());
        
        if (sshConfig.publicKeyData.startsWith("ssh-rsa")) {
            LOG_I("CONFIG", "Public key type: RSA");
        } else if (sshConfig.publicKeyData.startsWith("ssh-ed25519")) {
            LOG_I("CONFIG", "Public key type: Ed25519");
        } else if (sshConfig.publicKeyData.startsWith("ecdsa-sha2-")) {
            LOG_I("CONFIG", "Public key type: ECDSA");
        } else {
            LOG_W("CONFIG", "Public key type: Unknown");
        }
        
        // Extraire le premier mot (algorithme)
        int spaceIndex = sshConfig.publicKeyData.indexOf(' ');
        if (spaceIndex > 0) {
            String algorithm = sshConfig.publicKeyData.substring(0, spaceIndex);
            LOGF_I("CONFIG", "Public key algorithm: %s", algorithm.c_str());
        }
    }
    
    unlockConfig();
}

// Méthodes de configuration known hosts
void SSHConfiguration::setHostKeyVerification(bool enable) {
    if (lockConfig()) {
        sshConfig.verifyHostKey = enable;
        unlockConfig();
        
        LOGF_I("CONFIG", "Host key verification: %s", enable ? "enabled" : "disabled");
    }
}

void SSHConfiguration::setExpectedHostKey(const String& fingerprint, const String& keyType) {
    if (lockConfig()) {
        sshConfig.expectedHostKeyFingerprint = fingerprint;
        sshConfig.hostKeyType = keyType;
        unlockConfig();
        
        LOGF_I("CONFIG", "Expected host key set: %s (%s)", 
               fingerprint.c_str(), keyType.length() > 0 ? keyType.c_str() : "any type");
    }
}

void SSHConfiguration::setHostKeyVerification(const String& fingerprint, const String& keyType, bool enable) {
    if (lockConfig()) {
        sshConfig.verifyHostKey = enable;
        sshConfig.expectedHostKeyFingerprint = fingerprint;
        sshConfig.hostKeyType = keyType;
        unlockConfig();
        
        LOGF_I("CONFIG", "Host key verification configured: %s, fingerprint: %s, type: %s", 
               enable ? "enabled" : "disabled", 
               fingerprint.c_str(), 
               keyType.length() > 0 ? keyType.c_str() : "any type");
    }
}

void SSHConfiguration::setTunnelConfig(const String& remoteBindHost, int remoteBindPort, const String& localHost, int localPort) {
    if (lockConfig()) {
        tunnelConfig.remoteBindHost = remoteBindHost;
        tunnelConfig.remoteBindPort = remoteBindPort;
        tunnelConfig.localHost = localHost;
        tunnelConfig.localPort = localPort;
        unlockConfig();
        
        LOGF_I("CONFIG", "Tunnel configured: %s:%d -> %s:%d", 
               remoteBindHost.c_str(), remoteBindPort, localHost.c_str(), localPort);
    }
}

void SSHConfiguration::setConnectionConfig(int keepAliveInterval, int reconnectDelay, int maxReconnectAttempts, int connectionTimeout) {
    if (lockConfig()) {
        connectionConfig.keepAliveIntervalSec = keepAliveInterval;
        connectionConfig.reconnectDelayMs = reconnectDelay;
        connectionConfig.maxReconnectAttempts = maxReconnectAttempts;
        connectionConfig.connectionTimeoutSec = connectionTimeout;
        unlockConfig();
        
        LOGF_I("CONFIG", "Connection config: keepalive=%ds, reconnect_delay=%dms, max_attempts=%d, timeout=%ds",
               keepAliveInterval, reconnectDelay, maxReconnectAttempts, connectionTimeout);
    }
}

void SSHConfiguration::setBufferConfig(int bufferSize, int maxChannels, int channelTimeout) {
    if (lockConfig()) {
        connectionConfig.bufferSize = bufferSize;
        connectionConfig.maxChannels = maxChannels;
        connectionConfig.channelTimeoutMs = channelTimeout;
        unlockConfig();
        
        LOGF_I("CONFIG", "Buffer config: size=%d, max_channels=%d, channel_timeout=%dms",
               bufferSize, maxChannels, channelTimeout);
    }
}

void SSHConfiguration::setDebugConfig(bool enabled, int baudRate) {
    if (lockConfig()) {
        debugConfig.debugEnabled = enabled;
        debugConfig.serialBaudRate = baudRate;
        unlockConfig();
        
        LOGF_I("CONFIG", "Debug config: enabled=%s, baud_rate=%d", 
               enabled ? "true" : "false", baudRate);
    }
}

bool SSHConfiguration::validateConfiguration() const {
    return validateSSHConfig() && validateTunnelConfig() && validateConnectionConfig();
}

void SSHConfiguration::printConfiguration() const {
    if (lockConfig()) {
        LOG_I("CONFIG", "=== SSH Configuration ===");
        LOGF_I("CONFIG", "SSH Server: %s:%d", sshConfig.host.c_str(), sshConfig.port);
        LOGF_I("CONFIG", "SSH User: %s", sshConfig.username.c_str());
        LOGF_I("CONFIG", "SSH Auth: %s", sshConfig.useSSHKey ? "Key" : "Password");
        if (sshConfig.useSSHKey) {
            if (sshConfig.privateKeyData.length() > 0 && sshConfig.publicKeyData.length() > 0) {
                LOGF_I("CONFIG", "SSH Keys: In memory (private: %d bytes, public: %d bytes)", 
                       sshConfig.privateKeyData.length(), sshConfig.publicKeyData.length());
            } else {
                LOGF_I("CONFIG", "SSH Key: %s", sshConfig.privateKeyPath.c_str());
            }
        }
        
        LOG_I("CONFIG", "=== Tunnel Configuration ===");
        LOGF_I("CONFIG", "Remote Bind: %s:%d", tunnelConfig.remoteBindHost.c_str(), tunnelConfig.remoteBindPort);
        LOGF_I("CONFIG", "Local Target: %s:%d", tunnelConfig.localHost.c_str(), tunnelConfig.localPort);
        
        LOG_I("CONFIG", "=== Connection Configuration ===");
        LOGF_I("CONFIG", "Keep-alive: %ds", connectionConfig.keepAliveIntervalSec);
        LOGF_I("CONFIG", "Reconnect delay: %dms", connectionConfig.reconnectDelayMs);
        LOGF_I("CONFIG", "Max reconnect attempts: %d", connectionConfig.maxReconnectAttempts);
        LOGF_I("CONFIG", "Connection timeout: %ds", connectionConfig.connectionTimeoutSec);
        LOGF_I("CONFIG", "Buffer size: %d bytes", connectionConfig.bufferSize);
        LOGF_I("CONFIG", "Max channels: %d", connectionConfig.maxChannels);
        LOGF_I("CONFIG", "Channel timeout: %dms", connectionConfig.channelTimeoutMs);
        
        LOG_I("CONFIG", "=== Debug Configuration ===");
        LOGF_I("CONFIG", "Debug enabled: %s", debugConfig.debugEnabled ? "true" : "false");
        LOGF_I("CONFIG", "Serial baud rate: %d", debugConfig.serialBaudRate);
        
        unlockConfig();
    }
}

bool SSHConfiguration::lockConfig() const {
    if (configMutex == NULL) {
        return false;
    }
    return xSemaphoreTake(configMutex, portMAX_DELAY) == pdTRUE;
}

void SSHConfiguration::unlockConfig() const {
    if (configMutex != NULL) {
        xSemaphoreGive(configMutex);
    }
}

bool SSHConfiguration::validateSSHConfig() const {
    if (sshConfig.host.length() == 0) {
        LOG_E("CONFIG", "SSH host cannot be empty");
        return false;
    }
    
    if (sshConfig.port <= 0 || sshConfig.port > 65535) {
        LOG_E("CONFIG", "SSH port must be between 1 and 65535");
        return false;
    }
    
    if (sshConfig.username.length() == 0) {
        LOG_E("CONFIG", "SSH username cannot be empty");
        return false;
    }
    
    if (!sshConfig.useSSHKey && sshConfig.password.length() == 0) {
        LOG_E("CONFIG", "SSH password cannot be empty when not using key auth");
        return false;
    }
    
    if (sshConfig.useSSHKey) {
        // Vérifier si nous avons les clés en mémoire
        if (sshConfig.privateKeyData.length() > 0 && sshConfig.publicKeyData.length() > 0) {
            LOG_I("CONFIG", "SSH keys available in memory");
            return true;
        }
        
        // Sinon, vérifier le chemin du fichier
        if (sshConfig.privateKeyPath.length() == 0) {
            LOG_E("CONFIG", "SSH private key path cannot be empty when using key auth and keys not in memory");
            return false;
        }
    }
    
    return true;
}

bool SSHConfiguration::validateTunnelConfig() const {
    if (tunnelConfig.remoteBindHost.length() == 0) {
        LOG_E("CONFIG", "Remote bind host cannot be empty");
        return false;
    }
    
    if (tunnelConfig.remoteBindPort <= 0 || tunnelConfig.remoteBindPort > 65535) {
        LOG_E("CONFIG", "Remote bind port must be between 1 and 65535");
        return false;
    }
    
    if (tunnelConfig.localHost.length() == 0) {
        LOG_E("CONFIG", "Local host cannot be empty");
        return false;
    }
    
    if (tunnelConfig.localPort <= 0 || tunnelConfig.localPort > 65535) {
        LOG_E("CONFIG", "Local port must be between 1 and 65535");
        return false;
    }
    
    return true;
}

bool SSHConfiguration::validateConnectionConfig() const {
    if (connectionConfig.keepAliveIntervalSec <= 0) {
        LOG_E("CONFIG", "Keep-alive interval must be positive");
        return false;
    }
    
    if (connectionConfig.reconnectDelayMs <= 0) {
        LOG_E("CONFIG", "Reconnect delay must be positive");
        return false;
    }
    
    if (connectionConfig.maxReconnectAttempts <= 0) {
        LOG_E("CONFIG", "Max reconnect attempts must be positive");
        return false;
    }
    
    if (connectionConfig.connectionTimeoutSec <= 0) {
        LOG_E("CONFIG", "Connection timeout must be positive");
        return false;
    }
    
    if (connectionConfig.bufferSize <= 0) {
        LOG_E("CONFIG", "Buffer size must be positive");
        return false;
    }
    
    if (connectionConfig.maxChannels <= 0) {
        LOG_E("CONFIG", "Max channels must be positive");
        return false;
    }
    
    if (connectionConfig.channelTimeoutMs <= 0) {
        LOG_E("CONFIG", "Channel timeout must be positive");
        return false;
    }
    
    return true;
}