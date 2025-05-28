#ifndef SSH_TUNNEL_H
#define SSH_TUNNEL_H

#include <WiFiClient.h>
#include <libssh2.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include "config.h"
#include "logger.h"

enum TunnelState {
    TUNNEL_DISCONNECTED = 0,
    TUNNEL_CONNECTING = 1,
    TUNNEL_CONNECTED = 2,
    TUNNEL_ERROR = 3
};

struct TunnelChannel {
    LIBSSH2_CHANNEL* channel;
    int localSocket;
    bool active;
    unsigned long lastActivity;
};

class SSHTunnel {
public:
    SSHTunnel();
    ~SSHTunnel();
    
    bool init();
    bool connect();
    void disconnect();
    bool isConnected();
    void loop();
    TunnelState getState();
    String getStateString();
    
    // Statistics
    unsigned long getBytesReceived();
    unsigned long getBytesSent();
    int getActiveChannels();

private:
    // SSH connection management
    bool initializeSSH();
    bool authenticateSSH();
    bool createReverseTunnel();
    void cleanupSSH();
    
    // Channel management
    bool handleNewConnection();
    void handleChannelData(int channelIndex);
    void closeChannel(int channelIndex);
    void cleanupInactiveChannels();
    
    // Connection monitoring
    void sendKeepAlive();
    bool checkConnection();
    void handleReconnection();
    
    // Utility functions for WiFiClient callbacks
    static ssize_t wifiClientSend(libssh2_socket_t socket, const void *buffer, size_t length, int flags, void **abstract);
    static ssize_t wifiClientRecv(libssh2_socket_t socket, void *buffer, size_t length, int flags, void **abstract);
    
    // Member variables
    LIBSSH2_SESSION* session;
    LIBSSH2_LISTENER* listener;
    WiFiClient sshClient;
    TunnelChannel channels[MAX_CHANNELS];
    
    TunnelState state;
    unsigned long lastKeepAlive;
    unsigned long lastConnectionAttempt;
    int reconnectAttempts;
    
    // Statistics
    unsigned long bytesReceived;
    unsigned long bytesSent;
    
    // Buffers
    uint8_t rxBuffer[BUFFER_SIZE];
    uint8_t txBuffer[BUFFER_SIZE];
};

#endif
