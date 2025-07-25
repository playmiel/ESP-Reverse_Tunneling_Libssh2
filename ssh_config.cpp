#include "ssh_config.h"
#include "logger.h"

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
        unlockConfig();
        
        LOGF_I("CONFIG", "SSH key auth configured: %s:%d (user: %s, key: %s)", 
               host.c_str(), port, username.c_str(), privateKeyPath.c_str());
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
            LOGF_I("CONFIG", "SSH Key: %s", sshConfig.privateKeyPath.c_str());
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
    
    if (sshConfig.useSSHKey && sshConfig.privateKeyPath.length() == 0) {
        LOG_E("CONFIG", "SSH private key path cannot be empty when using key auth");
        return false;
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