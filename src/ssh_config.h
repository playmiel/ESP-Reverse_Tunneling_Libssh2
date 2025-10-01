#ifndef SSH_CONFIG_H
#define SSH_CONFIG_H

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

// Structure for SSH configuration
struct SSHServerConfig {
    String host;
    int port;
    String username;
    String password;
    bool useSSHKey;
    String privateKeyPath;  // Kept for compatibility
    String privateKeyData; // Private key content in memory
    String publicKeyData;  // Public key content in memory
    
    // Configuration known hosts
    bool verifyHostKey;     // Enable/disable verification
    String expectedHostKeyFingerprint; // Expected SHA256 fingerprint
    String hostKeyType;     // Expected key type (ssh-ed25519, ssh-rsa, etc.)
    
    // Default constructor
    SSHServerConfig() : 
        host("your-remote-server.com"),
        port(22),
        username("your_username"),
        password("your_password"),
        useSSHKey(false),
        privateKeyPath("/ssh_key"),
        privateKeyData(""),
        publicKeyData(""),
        verifyHostKey(false),
        expectedHostKeyFingerprint(""),
        hostKeyType("") {}
};

// Structure for tunnel configuration
struct TunnelConfig {
    String remoteBindHost;
    int remoteBindPort;
    String localHost;
    int localPort;
    
    // Default constructor
    TunnelConfig() :
        remoteBindHost("0.0.0.0"),
        remoteBindPort(8080),
        localHost("192.168.1.100"),
        localPort(80) {}
};

// Structure for connection management
struct ConnectionConfig {
    int keepAliveIntervalSec;
    int reconnectDelayMs;
    int maxReconnectAttempts;
    int connectionTimeoutSec;
    int bufferSize;
    int maxChannels;
    int channelTimeoutMs;
    uint8_t defaultChannelPriority;
    uint8_t priorityWeightLow;
    uint8_t priorityWeightNormal;
    uint8_t priorityWeightHigh;

    // Default constructor
    ConnectionConfig() :
        keepAliveIntervalSec(30),
        reconnectDelayMs(5000),
        maxReconnectAttempts(5),
        connectionTimeoutSec(30),
        bufferSize(8192),
    maxChannels(10),  // Increased from 5 to 10 for large transfers
        channelTimeoutMs(1800000),
        defaultChannelPriority(1),
        priorityWeightLow(1),
        priorityWeightNormal(2),
        priorityWeightHigh(4) {}
};

// Structure for debug configuration
struct DebugConfig {
    bool debugEnabled;
    int serialBaudRate;
    
    // Default constructor
    DebugConfig() :
        debugEnabled(true),
        serialBaudRate(115200) {}
};

// Main configuration class
class SSHConfiguration {
public:
    SSHConfiguration();
    ~SSHConfiguration();
    
    // SSH configuration methods
    void setSSHServer(const String& host, int port, const String& username, const String& password);
    void setSSHKeyAuth(const String& host, int port, const String& username, const String& privateKeyPath, const String& passphrase = "");
    void setSSHKeyAuthFromMemory(const String& host, int port, const String& username, const String& privateKeyData, const String& publicKeyData, const String& passphrase = "");
    
    // Utility methods to load keys
    bool loadSSHKeysFromFile(const String& privateKeyPath);
    bool loadSSHKeysFromLittleFS(const String& privateKeyPath);
    void setSSHKeysInMemory(const String& privateKeyData, const String& publicKeyData);
    bool validateSSHKeys() const;
    void diagnoseSSHKeys() const;
    
    // Known hosts configuration methods
    void setHostKeyVerification(bool enable);
    void setExpectedHostKey(const String& fingerprint, const String& keyType = "");
    void setHostKeyVerification(const String& fingerprint, const String& keyType = "", bool enable = true);
    
    // Tunnel configuration methods
    void setTunnelConfig(const String& remoteBindHost, int remoteBindPort, const String& localHost, int localPort);
    
    // Connection configuration methods
    void setConnectionConfig(int keepAliveInterval, int reconnectDelay, int maxReconnectAttempts, int connectionTimeout);
    void setBufferConfig(int bufferSize, int maxChannels, int channelTimeout);
    void setChannelPriorityProfile(uint8_t defaultPriority, uint8_t lowWeight = 1, uint8_t normalWeight = 2, uint8_t highWeight = 4);

    // Debug configuration methods
    void setDebugConfig(bool enabled, int baudRate);
    
    // Getters to access configurations
    const SSHServerConfig& getSSHConfig() const { return sshConfig; }
    const TunnelConfig& getTunnelConfig() const { return tunnelConfig; }
    const ConnectionConfig& getConnectionConfig() const { return connectionConfig; }
    const DebugConfig& getDebugConfig() const { return debugConfig; }
    
    // Validation methods
    bool validateConfiguration() const;
    void printConfiguration() const;
    
    // Thread-safe protection
    bool lockConfig() const;
    void unlockConfig() const;

private:
    SSHServerConfig sshConfig;
    TunnelConfig tunnelConfig;
    ConnectionConfig connectionConfig;
    DebugConfig debugConfig;
    
    // Semaphore for thread-safe protection
    SemaphoreHandle_t configMutex;
    
    // Private validation methods
    bool validateSSHConfig() const;
    bool validateTunnelConfig() const;
    bool validateConnectionConfig() const;
};

// Global configuration instance
extern SSHConfiguration globalSSHConfig;

// Compatibility macros for legacy code (optional)
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
