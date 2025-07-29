#ifndef SSH_CONFIG_H
#define SSH_CONFIG_H

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

// Structure pour la configuration SSH
struct SSHServerConfig {
    String host;
    int port;
    String username;
    String password;
    bool useSSHKey;
    String privateKeyPath;
    
    // Constructeur par défaut
    SSHServerConfig() : 
        host("your-remote-server.com"),
        port(22),
        username("your_username"),
        password("your_password"),
        useSSHKey(false),
        privateKeyPath("/ssh_key") {}
};

// Structure pour la configuration du tunnel
struct TunnelConfig {
    String remoteBindHost;
    int remoteBindPort;
    String localHost;
    int localPort;
    
    // Constructeur par défaut
    TunnelConfig() :
        remoteBindHost("0.0.0.0"),
        remoteBindPort(8080),
        localHost("192.168.1.100"),
        localPort(80) {}
};

// Structure pour la gestion des connexions
struct ConnectionConfig {
    int keepAliveIntervalSec;
    int reconnectDelayMs;
    int maxReconnectAttempts;
    int connectionTimeoutSec;
    int bufferSize;
    int maxChannels;
    int channelTimeoutMs;
    
    // Constructeur par défaut
    ConnectionConfig() :
        keepAliveIntervalSec(30),
        reconnectDelayMs(5000),
        maxReconnectAttempts(5),
        connectionTimeoutSec(30),
        bufferSize(8192),
        maxChannels(10),  // Augmenté de 5 à 10 pour les gros transferts
        channelTimeoutMs(1800000) {}
};

// Structure pour la configuration de debug
struct DebugConfig {
    bool debugEnabled;
    int serialBaudRate;
    
    // Constructeur par défaut
    DebugConfig() :
        debugEnabled(true),
        serialBaudRate(115200) {}
};

// Classe principale de configuration
class SSHConfiguration {
public:
    SSHConfiguration();
    ~SSHConfiguration();
    
    // Méthodes de configuration SSH
    void setSSHServer(const String& host, int port, const String& username, const String& password);
    void setSSHKeyAuth(const String& host, int port, const String& username, const String& privateKeyPath, const String& passphrase = "");
    
    // Méthodes de configuration du tunnel
    void setTunnelConfig(const String& remoteBindHost, int remoteBindPort, const String& localHost, int localPort);
    
    // Méthodes de configuration de connexion
    void setConnectionConfig(int keepAliveInterval, int reconnectDelay, int maxReconnectAttempts, int connectionTimeout);
    void setBufferConfig(int bufferSize, int maxChannels, int channelTimeout);
    
    // Méthodes de configuration debug
    void setDebugConfig(bool enabled, int baudRate);
    
    // Getters pour accéder aux configurations
    const SSHServerConfig& getSSHConfig() const { return sshConfig; }
    const TunnelConfig& getTunnelConfig() const { return tunnelConfig; }
    const ConnectionConfig& getConnectionConfig() const { return connectionConfig; }
    const DebugConfig& getDebugConfig() const { return debugConfig; }
    
    // Méthodes de validation
    bool validateConfiguration() const;
    void printConfiguration() const;
    
    // Protection thread-safe
    bool lockConfig() const;
    void unlockConfig() const;

private:
    SSHServerConfig sshConfig;
    TunnelConfig tunnelConfig;
    ConnectionConfig connectionConfig;
    DebugConfig debugConfig;
    
    // Sémaphore pour la protection thread-safe
    SemaphoreHandle_t configMutex;
    
    // Méthodes de validation privées
    bool validateSSHConfig() const;
    bool validateTunnelConfig() const;
    bool validateConnectionConfig() const;
};

// Instance globale de configuration
extern SSHConfiguration globalSSHConfig;

// Macros de compatibilité pour l'ancien code (optionnel)
#define SSH_HOST globalSSHConfig.getSSHConfig().host.c_str()
#define SSH_PORT globalSSHConfig.getSSHConfig().port
#define SSH_USERNAME globalSSHConfig.getSSHConfig().username.c_str()
#define SSH_PASSWORD globalSSHConfig.getSSHConfig().password.c_str()
#define USE_SSH_KEY globalSSHConfig.getSSHConfig().useSSHKey
#define SSH_PRIVATE_KEY_PATH globalSSHConfig.getSSHConfig().privateKeyPath.c_str()

#define REMOTE_BIND_HOST globalSSHConfig.getTunnelConfig().remoteBindHost.c_str()
#define REMOTE_BIND_PORT globalSSHConfig.getTunnelConfig().remoteBindPort
#define LOCAL_HOST globalSSHConfig.getTunnelConfig().localHost.c_str()
#define LOCAL_PORT globalSSHConfig.getTunnelConfig().localPort

#define KEEPALIVE_INTERVAL_SEC globalSSHConfig.getConnectionConfig().keepAliveIntervalSec
#define RECONNECT_DELAY_MS globalSSHConfig.getConnectionConfig().reconnectDelayMs
#define MAX_RECONNECT_ATTEMPTS globalSSHConfig.getConnectionConfig().maxReconnectAttempts
#define CONNECTION_TIMEOUT_SEC globalSSHConfig.getConnectionConfig().connectionTimeoutSec
#define BUFFER_SIZE globalSSHConfig.getConnectionConfig().bufferSize
#define MAX_CHANNELS globalSSHConfig.getConnectionConfig().maxChannels
#define CHANNEL_TIMEOUT_MS globalSSHConfig.getConnectionConfig().channelTimeoutMs

#define DEBUG_ENABLED globalSSHConfig.getDebugConfig().debugEnabled
#define SERIAL_BAUD_RATE globalSSHConfig.getDebugConfig().serialBaudRate

#endif