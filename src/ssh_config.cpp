#include "ssh_config.h"
#include "LittleFS.h"
#include "logger.h"

// Global configuration instance
SSHConfiguration globalSSHConfig;

SSHConfiguration::SSHConfiguration() {
  // Create semaphore for thread-safe protection
  configMutex = xSemaphoreCreateMutex();
  if (configMutex == NULL) {
    LOG_E("CONFIG", "Failed to create configuration mutex");
  }
  tunnelMappings.emplace_back();
}

SSHConfiguration::~SSHConfiguration() {
  if (configMutex != NULL) {
    vSemaphoreDelete(configMutex);
  }
}

void SSHConfiguration::setSSHServer(const String &host, int port,
                                    const String &username,
                                    const String &password) {
  if (lockConfig()) {
    sshConfig.host = host;
    sshConfig.port = port;
    sshConfig.username = username;
    sshConfig.password = password;
    sshConfig.useSSHKey = false;
    unlockConfig();

    LOGF_I("CONFIG", "SSH server configured: %s:%d (user: %s)", host.c_str(),
           port, username.c_str());
  }
}

void SSHConfiguration::setSSHKeyAuth(const String &host, int port,
                                     const String &username,
                                     const String &privateKeyPath,
                                     const String &passphrase) {
  if (lockConfig()) {
    sshConfig.host = host;
    sshConfig.port = port;
    sshConfig.username = username;
    sshConfig.privateKeyPath = privateKeyPath;
    sshConfig.password = passphrase; // Used as passphrase for the key
    sshConfig.useSSHKey = true;

    // Try to load keys from LittleFS
    if (!loadSSHKeysFromLittleFS(privateKeyPath)) {
      LOGF_W("CONFIG", "Could not load SSH keys from LittleFS: %s",
             privateKeyPath.c_str());
    }

    unlockConfig();

    LOGF_I("CONFIG", "SSH key auth configured: %s:%d (user: %s, key: %s)",
           host.c_str(), port, username.c_str(), privateKeyPath.c_str());
  }
}

void SSHConfiguration::setSSHKeyAuthFromMemory(const String &host, int port,
                                               const String &username,
                                               const String &privateKeyData,
                                               const String &publicKeyData,
                                               const String &passphrase) {
  if (lockConfig()) {
    sshConfig.host = host;
    sshConfig.port = port;
    sshConfig.username = username;
    sshConfig.privateKeyData = privateKeyData;
    sshConfig.publicKeyData = publicKeyData;
    sshConfig.password = passphrase; // Used as passphrase for the key
    sshConfig.useSSHKey = true;
    unlockConfig();

    LOGF_I("CONFIG", "SSH key auth from memory configured: %s:%d (user: %s)",
           host.c_str(), port, username.c_str());
  }
}

bool SSHConfiguration::loadSSHKeysFromLittleFS(const String &privateKeyPath) {
  // Load private key
  File privateKeyFile = LittleFS.open(privateKeyPath, "r");
  if (!privateKeyFile) {
    LOGF_E("CONFIG", "Cannot open private key file: %s",
           privateKeyPath.c_str());
    return false;
  }

  sshConfig.privateKeyData = privateKeyFile.readString();
  privateKeyFile.close();

  if (sshConfig.privateKeyData.length() == 0) {
    LOG_E("CONFIG", "Private key file is empty");
    return false;
  }

  // Load public key (usually .pub)
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

  LOGF_I("CONFIG",
         "SSH keys loaded from LittleFS (private: %d bytes, public: %d bytes)",
         sshConfig.privateKeyData.length(), sshConfig.publicKeyData.length());

  return true;
}

bool SSHConfiguration::loadSSHKeysFromFile(const String &privateKeyPath) {
  // This method can be used for other file systems
  // For now, we use LittleFS
  return loadSSHKeysFromLittleFS(privateKeyPath);
}

void SSHConfiguration::setSSHKeysInMemory(const String &privateKeyData,
                                          const String &publicKeyData) {
  if (lockConfig()) {
    // Clean and validate keys
    String cleanPrivateKey = privateKeyData;
    String cleanPublicKey = publicKeyData;

    // Ensure keys end with a newline
    if (!cleanPrivateKey.endsWith("\n")) {
      cleanPrivateKey += "\n";
    }
    if (!cleanPublicKey.endsWith("\n")) {
      cleanPublicKey += "\n";
    }

    // Replace Windows line endings with Unix if needed
    cleanPrivateKey.replace("\r\n", "\n");
    cleanPublicKey.replace("\r\n", "\n");

    sshConfig.privateKeyData = cleanPrivateKey;
    sshConfig.publicKeyData = cleanPublicKey;
    unlockConfig();

    LOGF_I("CONFIG",
           "SSH keys set in memory (private: %d bytes, public: %d bytes)",
           cleanPrivateKey.length(), cleanPublicKey.length());

    // Basic key validation
    if (cleanPrivateKey.indexOf("-----BEGIN") == -1 ||
        cleanPrivateKey.indexOf("-----END") == -1) {
      LOG_W("CONFIG", "Private key might not be properly formatted");
    }
    if (cleanPublicKey.indexOf("ssh-") != 0 &&
        cleanPublicKey.indexOf("ecdsa-") != 0) {
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
      LOG_E("CONFIG",
            "Public key doesn't start with proper algorithm identifier");
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

  // Analyze private key
  if (sshConfig.privateKeyData.length() > 0) {
    LOGF_I("CONFIG", "Private key length: %d bytes",
           sshConfig.privateKeyData.length());

    if (sshConfig.privateKeyData.indexOf(
            "-----BEGIN OPENSSH PRIVATE KEY-----") != -1) {
      LOG_I("CONFIG", "Private key format: OpenSSH modern format");
      LOG_W("CONFIG", "Note: OpenSSH format may not be fully supported by all "
                      "libssh2 versions");
    } else if (sshConfig.privateKeyData.indexOf(
                   "-----BEGIN RSA PRIVATE KEY-----") != -1) {
      LOG_I("CONFIG", "Private key format: RSA PEM format");
    } else if (sshConfig.privateKeyData.indexOf(
                   "-----BEGIN EC PRIVATE KEY-----") != -1) {
      LOG_I("CONFIG", "Private key format: EC PEM format");
    } else if (sshConfig.privateKeyData.indexOf(
                   "-----BEGIN PRIVATE KEY-----") != -1) {
      LOG_I("CONFIG", "Private key format: PKCS#8 PEM format");
    } else {
      LOG_W("CONFIG", "Private key format: Unknown or invalid");
    }

    // Check line endings
    if (sshConfig.privateKeyData.indexOf("\r\n") != -1) {
      LOG_W("CONFIG", "Private key contains Windows line endings (CRLF)");
    } else if (sshConfig.privateKeyData.indexOf("\n") != -1) {
      LOG_I("CONFIG", "Private key uses Unix line endings (LF)");
    } else {
      LOG_W("CONFIG", "Private key might not have proper line endings");
    }
  }

  // Analyze public key
  if (sshConfig.publicKeyData.length() > 0) {
    LOGF_I("CONFIG", "Public key length: %d bytes",
           sshConfig.publicKeyData.length());

    if (sshConfig.publicKeyData.startsWith("ssh-rsa")) {
      LOG_I("CONFIG", "Public key type: RSA");
    } else if (sshConfig.publicKeyData.startsWith("ssh-ed25519")) {
      LOG_I("CONFIG", "Public key type: Ed25519");
    } else if (sshConfig.publicKeyData.startsWith("ecdsa-sha2-")) {
      LOG_I("CONFIG", "Public key type: ECDSA");
    } else {
      LOG_W("CONFIG", "Public key type: Unknown");
    }

    // Extract the first word (algorithm)
    int spaceIndex = sshConfig.publicKeyData.indexOf(' ');
    if (spaceIndex > 0) {
      String algorithm = sshConfig.publicKeyData.substring(0, spaceIndex);
      LOGF_I("CONFIG", "Public key algorithm: %s", algorithm.c_str());
    }
  }

  unlockConfig();
}

// Known hosts configuration methods
void SSHConfiguration::setHostKeyVerification(bool enable) {
  if (lockConfig()) {
    sshConfig.verifyHostKey = enable;
    unlockConfig();

    LOGF_I("CONFIG", "Host key verification: %s",
           enable ? "enabled" : "disabled");
  }
}

void SSHConfiguration::setExpectedHostKey(const String &fingerprint,
                                          const String &keyType) {
  if (lockConfig()) {
    sshConfig.expectedHostKeyFingerprint = fingerprint;
    sshConfig.hostKeyType = keyType;
    unlockConfig();

    LOGF_I("CONFIG", "Expected host key set: %s (%s)", fingerprint.c_str(),
           keyType.length() > 0 ? keyType.c_str() : "any type");
  }
}

void SSHConfiguration::setHostKeyVerification(const String &fingerprint,
                                              const String &keyType,
                                              bool enable) {
  if (lockConfig()) {
    sshConfig.verifyHostKey = enable;
    sshConfig.expectedHostKeyFingerprint = fingerprint;
    sshConfig.hostKeyType = keyType;
    unlockConfig();

    LOGF_I("CONFIG",
           "Host key verification configured: %s, fingerprint: %s, type: %s",
           enable ? "enabled" : "disabled", fingerprint.c_str(),
           keyType.length() > 0 ? keyType.c_str() : "any type");
  }
}

void SSHConfiguration::setHostKeyMismatchCallback(
    HostKeyMismatchCallback callback, void *context) {
  if (lockConfig()) {
    sshConfig.onHostKeyMismatch = callback;
    sshConfig.hostKeyMismatchContext = context;
    unlockConfig();

    LOGF_I("CONFIG", "Host key mismatch callback %s",
           callback ? "registered" : "cleared");
  }
}

void SSHConfiguration::setTunnelConfig(const String &remoteBindHost,
                                       int remoteBindPort,
                                       const String &localHost, int localPort) {
  TunnelConfig mapping;
  mapping.remoteBindHost = remoteBindHost;
  mapping.remoteBindPort = remoteBindPort;
  mapping.localHost = localHost;
  mapping.localPort = localPort;

  if (lockConfig()) {
    tunnelMappings.clear();
    tunnelMappings.push_back(mapping);
    unlockConfig();

    LOGF_I("CONFIG",
           "Tunnel configuration reset to single mapping: %s:%d -> %s:%d",
           remoteBindHost.c_str(), remoteBindPort, localHost.c_str(),
           localPort);
  }
}

void SSHConfiguration::addTunnelMapping(const String &remoteBindHost,
                                        int remoteBindPort,
                                        const String &localHost,
                                        int localPort) {
  TunnelConfig mapping;
  mapping.remoteBindHost = remoteBindHost;
  mapping.remoteBindPort = remoteBindPort;
  mapping.localHost = localHost;
  mapping.localPort = localPort;
  addTunnelMapping(mapping);
}

void SSHConfiguration::addTunnelMapping(const TunnelConfig &mapping) {
  if (lockConfig()) {
    tunnelMappings.push_back(mapping);
    size_t idx = tunnelMappings.size() - 1;
    unlockConfig();

    LOGF_I("CONFIG", "Tunnel mapping #%u added: %s:%d -> %s:%d", (unsigned)idx,
           mapping.remoteBindHost.c_str(), mapping.remoteBindPort,
           mapping.localHost.c_str(), mapping.localPort);
  }
}

bool SSHConfiguration::removeTunnelMapping(size_t index) {
  bool removed = false;
  if (lockConfig()) {
    if (index < tunnelMappings.size()) {
      tunnelMappings.erase(tunnelMappings.begin() + index);
      removed = true;
      LOGF_I("CONFIG", "Tunnel mapping #%u removed", (unsigned)index);
    } else {
      LOGF_W("CONFIG", "Cannot remove tunnel mapping #%u (out of range)",
             (unsigned)index);
    }
    unlockConfig();
  }
  return removed;
}

void SSHConfiguration::clearTunnelMappings() {
  if (lockConfig()) {
    tunnelMappings.clear();
    unlockConfig();
    LOG_I("CONFIG", "All tunnel mappings cleared");
  }
}

void SSHConfiguration::setConnectionConfig(int keepAliveInterval,
                                           int reconnectDelay,
                                           int maxReconnectAttempts,
                                           int connectionTimeout) {
  if (lockConfig()) {
    connectionConfig.keepAliveIntervalSec = keepAliveInterval;
    connectionConfig.libssh2KeepAliveIntervalSec = keepAliveInterval;
    connectionConfig.reconnectDelayMs = reconnectDelay;
    connectionConfig.maxReconnectAttempts = maxReconnectAttempts;
    connectionConfig.connectionTimeoutSec = connectionTimeout;
    unlockConfig();

    LOGF_I("CONFIG",
           "Connection config: keepalive=%ds, reconnect_delay=%dms, "
           "max_attempts=%d, timeout=%ds",
           keepAliveInterval, reconnectDelay, maxReconnectAttempts,
           connectionTimeout);
  }
}

void SSHConfiguration::setBufferConfig(int bufferSize, int maxChannels,
                                       int channelTimeout,
                                       size_t tunnelRingBufferSize) {
  if (lockConfig()) {
    connectionConfig.bufferSize = bufferSize;
    connectionConfig.maxChannels = maxChannels;
    connectionConfig.channelTimeoutMs = channelTimeout;
    connectionConfig.tunnelRingBufferSize = tunnelRingBufferSize;
    unlockConfig();

    LOGF_I("CONFIG",
           "Buffer config: size=%d, max_channels=%d, channel_timeout=%dms, "
           "ring_buffer=%u bytes",
           bufferSize, maxChannels, channelTimeout,
           (unsigned)tunnelRingBufferSize);
  }
}

void SSHConfiguration::setMaxReverseListeners(int maxListeners) {
  if (maxListeners <= 0) {
    LOG_W("CONFIG", "Max reverse listeners must be positive");
    return;
  }
  if (lockConfig()) {
    connectionConfig.maxReverseListeners = maxListeners;
    unlockConfig();
    LOGF_I("CONFIG", "Max reverse listeners set to %d", maxListeners);
  }
}

void SSHConfiguration::setKeepAliveOptions(bool enableLibssh2,
                                           int intervalSeconds) {
  if (intervalSeconds <= 0) {
    intervalSeconds = connectionConfig.keepAliveIntervalSec;
  }
  if (lockConfig()) {
    connectionConfig.libssh2KeepAliveEnabled = enableLibssh2;
    connectionConfig.libssh2KeepAliveIntervalSec = intervalSeconds;
    unlockConfig();

    LOGF_I("CONFIG", "libssh2 keepalive: %s (interval=%ds)",
           enableLibssh2 ? "enabled" : "disabled", intervalSeconds);
  }
}

void SSHConfiguration::setDataTaskConfig(uint16_t stackSize,
                                         int8_t coreAffinity) {
  if (stackSize == 0) {
    stackSize = connectionConfig.dataTaskStackSize;
  }
  if (lockConfig()) {
    connectionConfig.dataTaskStackSize = stackSize;
    connectionConfig.dataTaskCoreAffinity = coreAffinity;
    unlockConfig();

    LOGF_I("CONFIG", "Data task config: stack=%u bytes, core=%d", stackSize,
           coreAffinity);
  }
}

void SSHConfiguration::setChannelPriorityProfile(uint8_t defaultPriority,
                                                 uint8_t lowWeight,
                                                 uint8_t normalWeight,
                                                 uint8_t highWeight) {
  if (lockConfig()) {
    if (lowWeight == 0) {
      lowWeight = 1;
    }
    if (normalWeight == 0) {
      normalWeight = 1;
    }
    if (highWeight == 0) {
      highWeight = 1;
    }

    connectionConfig.defaultChannelPriority =
        (defaultPriority > 2) ? 2 : defaultPriority;
    connectionConfig.priorityWeightLow = lowWeight;
    connectionConfig.priorityWeightNormal = normalWeight;
    connectionConfig.priorityWeightHigh = highWeight;
    unlockConfig();

    LOGF_I("CONFIG",
           "Channel priority profile: default=%u, weights(L/M/H)=%u/%u/%u",
           connectionConfig.defaultChannelPriority,
           connectionConfig.priorityWeightLow,
           connectionConfig.priorityWeightNormal,
           connectionConfig.priorityWeightHigh);
  }
}

void SSHConfiguration::setGlobalRateLimit(size_t bytesPerSecond,
                                          size_t burstBytes) {
  if (lockConfig()) {
    connectionConfig.globalRateLimitBytesPerSec = bytesPerSecond;
    connectionConfig.globalBurstBytes = burstBytes;
    unlockConfig();

    if (bytesPerSecond == 0) {
      LOG_I("CONFIG", "Global rate limit disabled");
    } else {
      LOGF_I("CONFIG", "Global rate limit: %zu B/s (burst=%zu)", bytesPerSecond,
             burstBytes ? burstBytes : bytesPerSecond);
    }
  }
}

void SSHConfiguration::setDebugConfig(bool enabled, int baudRate) {
  if (lockConfig()) {
    debugConfig.debugEnabled = enabled;
    debugConfig.serialBaudRate = baudRate;
    debugConfig.minLogLevel = enabled ? LOG_DEBUG : LOG_WARN;
    unlockConfig();

    LOGF_I("CONFIG", "Debug config: enabled=%s, baud_rate=%d, min_level=%d",
           enabled ? "true" : "false", baudRate, debugConfig.minLogLevel);
  }
}

void SSHConfiguration::setLogLevel(LogLevel level) {
  if (lockConfig()) {
    debugConfig.minLogLevel = level;
    unlockConfig();

    LOGF_I("CONFIG", "Log level set to %d", level);
  }
}

bool SSHConfiguration::validateConfiguration() const {
  return validateSSHConfig() && validateTunnelConfig() &&
         validateConnectionConfig();
}

void SSHConfiguration::printConfiguration() const {
  if (lockConfig()) {
    LOG_I("CONFIG", "=== SSH Configuration ===");
    LOGF_I("CONFIG", "SSH Server: %s:%d", sshConfig.host.c_str(),
           sshConfig.port);
    LOGF_I("CONFIG", "SSH User: %s", sshConfig.username.c_str());
    LOGF_I("CONFIG", "SSH Auth: %s", sshConfig.useSSHKey ? "Key" : "Password");
    if (sshConfig.useSSHKey) {
      if (sshConfig.privateKeyData.length() > 0 &&
          sshConfig.publicKeyData.length() > 0) {
        LOGF_I("CONFIG",
               "SSH Keys: In memory (private: %d bytes, public: %d bytes)",
               sshConfig.privateKeyData.length(),
               sshConfig.publicKeyData.length());
      } else {
        LOGF_I("CONFIG", "SSH Key: %s", sshConfig.privateKeyPath.c_str());
      }
    }

    LOG_I("CONFIG", "=== Tunnel Configuration ===");
    if (tunnelMappings.empty()) {
      LOG_W("CONFIG", "No tunnel mappings configured");
    } else {
      for (size_t i = 0; i < tunnelMappings.size(); ++i) {
        const TunnelConfig &mapping = tunnelMappings[i];
        LOGF_I("CONFIG", "#%u Remote Bind: %s:%d", (unsigned)i,
               mapping.remoteBindHost.c_str(), mapping.remoteBindPort);
        LOGF_I("CONFIG", "#%u Local Target: %s:%d", (unsigned)i,
               mapping.localHost.c_str(), mapping.localPort);
      }
    }

    LOG_I("CONFIG", "=== Connection Configuration ===");
    LOGF_I("CONFIG", "Keep-alive: %ds", connectionConfig.keepAliveIntervalSec);
    LOGF_I("CONFIG", "libssh2 keep-alive: %s (%ds)",
           connectionConfig.libssh2KeepAliveEnabled ? "enabled" : "disabled",
           connectionConfig.libssh2KeepAliveIntervalSec);
    LOGF_I("CONFIG", "Reconnect delay: %dms",
           connectionConfig.reconnectDelayMs);
    LOGF_I("CONFIG", "Max reconnect attempts: %d",
           connectionConfig.maxReconnectAttempts);
    LOGF_I("CONFIG", "Connection timeout: %ds",
           connectionConfig.connectionTimeoutSec);
    LOGF_I("CONFIG", "Buffer size: %d bytes", connectionConfig.bufferSize);
    LOGF_I("CONFIG", "Max channels: %d", connectionConfig.maxChannels);
    LOGF_I("CONFIG", "Channel timeout: %dms",
           connectionConfig.channelTimeoutMs);
    LOGF_I("CONFIG", "Tunnel ring buffer: %u bytes",
           (unsigned)connectionConfig.tunnelRingBufferSize);
    LOGF_I("CONFIG", "Channel priority default: %u",
           connectionConfig.defaultChannelPriority);
    LOGF_I("CONFIG", "Channel priority weights (L/M/H): %u/%u/%u",
           connectionConfig.priorityWeightLow,
           connectionConfig.priorityWeightNormal,
           connectionConfig.priorityWeightHigh);
    LOGF_I("CONFIG", "Data task stack/core: %u / %d",
           connectionConfig.dataTaskStackSize,
           connectionConfig.dataTaskCoreAffinity);
    LOGF_I("CONFIG", "Max reverse listeners: %d",
           connectionConfig.maxReverseListeners);
    if (connectionConfig.globalRateLimitBytesPerSec > 0) {
      LOGF_I("CONFIG", "Global rate limit: %zu B/s (burst=%zu)",
             connectionConfig.globalRateLimitBytesPerSec,
             connectionConfig.globalBurstBytes
                 ? connectionConfig.globalBurstBytes
                 : connectionConfig.globalRateLimitBytesPerSec);
    } else {
      LOG_I("CONFIG", "Global rate limit: disabled");
    }

    LOG_I("CONFIG", "=== Debug Configuration ===");
    LOGF_I("CONFIG", "Debug enabled: %s",
           debugConfig.debugEnabled ? "true" : "false");
    LOGF_I("CONFIG", "Serial baud rate: %d", debugConfig.serialBaudRate);
    LOGF_I("CONFIG", "Log level threshold: %d", debugConfig.minLogLevel);

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
    // Check if we have keys in memory
    if (sshConfig.privateKeyData.length() > 0 &&
        sshConfig.publicKeyData.length() > 0) {
      LOG_I("CONFIG", "SSH keys available in memory");
      return true;
    }

    // Otherwise, check the file path
    if (sshConfig.privateKeyPath.length() == 0) {
      LOG_E("CONFIG", "SSH private key path cannot be empty when using key "
                      "auth and keys not in memory");
      return false;
    }
  }

  return true;
}

bool SSHConfiguration::validateTunnelConfig() const {
  if (tunnelMappings.empty()) {
    LOG_E("CONFIG", "At least one tunnel mapping must be configured");
    return false;
  }

  for (size_t i = 0; i < tunnelMappings.size(); ++i) {
    const TunnelConfig &mapping = tunnelMappings[i];
    if (mapping.remoteBindHost.length() == 0) {
      LOGF_E("CONFIG", "Mapping #%u: Remote bind host cannot be empty",
             (unsigned)i);
      return false;
    }
    if (mapping.remoteBindPort <= 0 || mapping.remoteBindPort > 65535) {
      LOGF_E("CONFIG",
             "Mapping #%u: Remote bind port must be between 1 and "
             "65535",
             (unsigned)i);
      return false;
    }
    if (mapping.localHost.length() == 0) {
      LOGF_E("CONFIG", "Mapping #%u: Local host cannot be empty", (unsigned)i);
      return false;
    }
    if (mapping.localPort <= 0 || mapping.localPort > 65535) {
      LOGF_E("CONFIG", "Mapping #%u: Local port must be between 1 and 65535",
             (unsigned)i);
      return false;
    }
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

  if (connectionConfig.defaultChannelPriority > 2) {
    LOG_E("CONFIG", "Default channel priority must be between 0 and 2");
    return false;
  }

  if (connectionConfig.priorityWeightLow == 0 ||
      connectionConfig.priorityWeightNormal == 0 ||
      connectionConfig.priorityWeightHigh == 0) {
    LOG_E("CONFIG", "Channel priority weights must be greater than zero");
    return false;
  }

  if (connectionConfig.globalRateLimitBytesPerSec == 0 &&
      connectionConfig.globalBurstBytes > 0) {
    LOG_W("CONFIG", "Global burst is ignored when rate limit is disabled");
  }

  if (connectionConfig.libssh2KeepAliveEnabled &&
      connectionConfig.libssh2KeepAliveIntervalSec <= 0) {
    LOG_E("CONFIG",
          "libssh2 keep-alive interval must be positive when enabled");
    return false;
  }

  if (connectionConfig.tunnelRingBufferSize == 0) {
    LOG_E("CONFIG", "Tunnel ring buffer size must be positive");
    return false;
  }

  if (connectionConfig.dataTaskStackSize == 0) {
    LOG_E("CONFIG", "Data task stack size must be positive");
    return false;
  }

  if (connectionConfig.dataTaskCoreAffinity < -1) {
    LOG_E("CONFIG",
          "Data task core affinity must be -1 (no pin) or a valid core index");
    return false;
  }

  if (connectionConfig.maxReverseListeners <= 0) {
    LOG_E("CONFIG", "Max reverse listeners must be positive");
    return false;
  }

  return true;
}

const TunnelConfig &SSHConfiguration::getTunnelConfig(size_t index) const {
  static TunnelConfig fallback;
  if (tunnelMappings.empty()) {
    return fallback;
  }
  if (index >= tunnelMappings.size()) {
    return tunnelMappings.front();
  }
  return tunnelMappings[index];
}
