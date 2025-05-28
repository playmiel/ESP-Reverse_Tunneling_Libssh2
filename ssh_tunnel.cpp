#include "ssh_tunnel.h"

SSHTunnel::SSHTunnel() : 
    session(nullptr),
    listener(nullptr),
    state(TUNNEL_DISCONNECTED),
    lastKeepAlive(0),
    lastConnectionAttempt(0),
    reconnectAttempts(0),
    bytesReceived(0),
    bytesSent(0) {

    // Initialize channels
    for (int i = 0; i < MAX_CHANNELS; i++) {
        channels[i].channel = nullptr;
        channels[i].localSocket = -1;
        channels[i].active = false;
        channels[i].lastActivity = 0;
    }
}

SSHTunnel::~SSHTunnel() {
    disconnect();
}

bool SSHTunnel::init() {
    // Initialize libssh2
    int rc = libssh2_init(0);
    if (rc != 0) {
        LOGF_E("SSH", "libssh2 initialization failed: %d", rc);
        return false;
    }

    LOG_I("SSH", "SSH tunnel initialized");
    return true;
}

bool SSHTunnel::connect() {
    if (state == TUNNEL_CONNECTING) {
        return false; // Already attempting connection
    }

    unsigned long now = millis();
    if (now - lastConnectionAttempt < RECONNECT_DELAY_MS) {
        return false; // Too soon since last attempt
    }

    lastConnectionAttempt = now;
    state = TUNNEL_CONNECTING;

    LOG_I("SSH", "Attempting SSH connection...");

    // Connect to SSH server
    if (!sshClient.connect(SSH_HOST, SSH_PORT)) {
        LOGF_E("SSH", "Failed to connect to %s:%d", SSH_HOST, SSH_PORT);
        state = TUNNEL_ERROR;
        return false;
    }

    if (!initializeSSH()) {
        LOG_E("SSH", "SSH initialization failed");
        state = TUNNEL_ERROR;
        sshClient.stop();
        return false;
    }

    if (!authenticateSSH()) {
        LOG_E("SSH", "SSH authentication failed");
        state = TUNNEL_ERROR;
        cleanupSSH();
        return false;
    }

    if (!createReverseTunnel()) {
        LOG_E("SSH", "Failed to create reverse tunnel");
        state = TUNNEL_ERROR;
        cleanupSSH();
        return false;
    }

    state = TUNNEL_CONNECTED;
    reconnectAttempts = 0;
    lastKeepAlive = millis();

    LOGF_I("SSH", "Reverse tunnel established: %s:%d -> %s:%d", 
           REMOTE_BIND_HOST, REMOTE_BIND_PORT, LOCAL_HOST, LOCAL_PORT);

    return true;
}

void SSHTunnel::disconnect() {
    LOG_I("SSH", "Disconnecting SSH tunnel...");

    // Close all channels
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (channels[i].active) {
            closeChannel(i);
        }
    }

    cleanupSSH();
    sshClient.stop();
    state = TUNNEL_DISCONNECTED;

    LOG_I("SSH", "SSH tunnel disconnected");
}

bool SSHTunnel::isConnected() {
    return state == TUNNEL_CONNECTED;
}

void SSHTunnel::loop() {
    unsigned long now = millis();

    // Handle reconnection if needed
    if (state == TUNNEL_ERROR || (state == TUNNEL_CONNECTED && !checkConnection())) {
        handleReconnection();
        return;
    }

    if (state != TUNNEL_CONNECTED) {
        return;
    }

    // Send keep-alive
    if (now - lastKeepAlive > KEEPALIVE_INTERVAL_SEC * 1000) {
        sendKeepAlive();
        lastKeepAlive = now;
    }

    // Handle new connections
    handleNewConnection();

    // Handle data for existing channels
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (channels[i].active) {
            handleChannelData(i);
        }
    }

    // Cleanup inactive channels
    cleanupInactiveChannels();
}

bool SSHTunnel::initializeSSH() {
    session = libssh2_session_init();
    if (!session) {
        LOG_E("SSH", "Failed to create SSH session");
        return false;
    }

    // Set non-blocking mode
    libssh2_session_set_blocking(session, 0);

    // Set socket - callback not needed for basic functionality

    // Handshake
    int rc;
    int sock = sshClient.fd();
    while ((rc = libssh2_session_handshake(session, sock)) == LIBSSH2_ERROR_EAGAIN) {
        delay(10);
    }

    if (rc) {
        LOGF_E("SSH", "SSH handshake failed: %d", rc);
        return false;
    }

    LOG_I("SSH", "SSH handshake completed");
    return true;
}

bool SSHTunnel::authenticateSSH() {
    int rc;

    if (USE_SSH_KEY) {
        // Key-based authentication
        rc = libssh2_userauth_publickey_fromfile(session, SSH_USERNAME,
                                                 nullptr, SSH_PRIVATE_KEY_PATH, nullptr);
    } else {
        // Password authentication
        while ((rc = libssh2_userauth_password(session, SSH_USERNAME, SSH_PASSWORD)) == LIBSSH2_ERROR_EAGAIN) {
            delay(10);
        }
    }

    if (rc) {
        LOGF_E("SSH", "SSH authentication failed: %d", rc);
        return false;
    }

    LOG_I("SSH", "SSH authentication successful");
    return true;
}

bool SSHTunnel::createReverseTunnel() {
    int rc;
    int bound_port;
    int localPort = LOCAL_PORT; // Local port to bind to

    while ((rc = libssh2_channel_forward_listen_ex(session, REMOTE_BIND_HOST, REMOTE_BIND_PORT,
                                                   &localPort, NULL)) == LIBSSH2_ERROR_EAGAIN) {
        delay(10);
    }

    if (rc || !listener) {
        LOGF_E("SSH", "Failed to create reverse tunnel listener: %d", rc);
        return false;
    }

    LOGF_I("SSH", "Reverse tunnel listener created on port %d", bound_port);
    return true;
}

void SSHTunnel::cleanupSSH() {
    if (listener) {
        libssh2_channel_forward_cancel(listener);
        listener = nullptr;
    }

    if (session) {
        libssh2_session_disconnect(session, "Shutdown");
        libssh2_session_free(session);
        session = nullptr;
    }
}

bool SSHTunnel::handleNewConnection() {
    if (!listener) return false;

    LIBSSH2_CHANNEL* channel = libssh2_channel_forward_accept(listener);

    if (!channel) {
        return false; // No new connection or error
    }

    // Find available channel slot
    int channelIndex = -1;
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (!channels[i].active) {
            channelIndex = i;
            break;
        }
    }

    if (channelIndex == -1) {
        LOG_W("SSH", "No available channel slots, closing new connection");
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        return false;
    }

    // Create socket and connect to local endpoint
    int localSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (localSocket < 0) {
        LOG_E("SSH", "Failed to create local socket");
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        return false;
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LOCAL_PORT);
    inet_pton(AF_INET, LOCAL_HOST, &addr.sin_addr);
    
    if (connect(localSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOGF_E("SSH", "Failed to connect to local endpoint %s:%d", LOCAL_HOST, LOCAL_PORT);
        close(localSocket);
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        return false;
    }
    
    // Set socket non-blocking
    int flags = fcntl(localSocket, F_GETFL, 0);
    fcntl(localSocket, F_SETFL, flags | O_NONBLOCK);

    // Set up channel
    channels[channelIndex].channel = channel;
    channels[channelIndex].localSocket = localSocket;
    channels[channelIndex].active = true;
    channels[channelIndex].lastActivity = millis();

    libssh2_channel_set_blocking(channel, 0);

    LOGF_I("SSH", "New tunnel connection established (channel %d)", channelIndex);
    return true;
}

void SSHTunnel::handleChannelData(int channelIndex) {
    TunnelChannel& ch = channels[channelIndex];
    if (!ch.active || !ch.channel || ch.localSocket < 0) return;

    unsigned long now = millis();
    bool dataTransferred = false;

    // SSH -> Local
    ssize_t rc = libssh2_channel_read(ch.channel, (char*)rxBuffer, BUFFER_SIZE);
    if (rc > 0) {
        ssize_t written = send(ch.localSocket, rxBuffer, rc, MSG_DONTWAIT);
        if (written > 0) {
            bytesReceived += written;
            dataTransferred = true;
            LOGF_D("SSH", "Channel %d: SSH->Local %d bytes", channelIndex, written);
        }
    } else if (rc < 0 && rc != LIBSSH2_ERROR_EAGAIN) {
        LOGF_W("SSH", "Channel %d read error: %d", channelIndex, rc);
        closeChannel(channelIndex);
        return;
    }

    // Local -> SSH
    int available = ch.localClient.available();
    if (available > 0) {
        size_t toRead = min(available, (int)BUFFER_SIZE);
        size_t bytesRead = ch.localClient.readBytes(txBuffer, toRead);

        if (bytesRead > 0) {
            ssize_t written = libssh2_channel_write(ch.channel, (char*)txBuffer, bytesRead);
            if (written > 0) {
                bytesSent += written;
                dataTransferred = true;
                LOGF_D("SSH", "Channel %d: Local->SSH %d bytes", channelIndex, written);
            } else if (written < 0 && written != LIBSSH2_ERROR_EAGAIN) {
                LOGF_W("SSH", "Channel %d write error: %d", channelIndex, written);
                closeChannel(channelIndex);
                return;
            }
        }
    }

    // Check if channel is closed
    if (libssh2_channel_eof(ch.channel) || !ch.localClient.connected()) {
        LOGF_I("SSH", "Channel %d closed", channelIndex);
        closeChannel(channelIndex);
        return;
    }

    if (dataTransferred) {
        ch.lastActivity = now;
    }
}

void SSHTunnel::closeChannel(int channelIndex) {
    TunnelChannel& ch = channels[channelIndex];
    if (!ch.active) return;

    if (ch.channel) {
        libssh2_channel_close(ch.channel);
        libssh2_channel_free(ch.channel);
        ch.channel = nullptr;
    }

    if (ch.localClient.connected()) {
        ch.localClient.stop();
    }

    ch.active = false;
    ch.lastActivity = 0;

    LOGF_I("SSH", "Channel %d closed", channelIndex);
}

void SSHTunnel::cleanupInactiveChannels() {
    unsigned long now = millis();

    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (channels[i].active && (now - channels[i].lastActivity > 300000)) { // 5 minutes timeout
            LOGF_W("SSH", "Channel %d timeout, closing", i);
            closeChannel(i);
        }
    }
}

void SSHTunnel::sendKeepAlive() {
    if (!session) return;

    int seconds = 0;
    int rc = libssh2_keepalive_send(session, &seconds);
    if (rc == 0) {
        LOGF_D("SSH", "Keep-alive sent, next in %d seconds", seconds);
    } else if (rc != LIBSSH2_ERROR_EAGAIN) {
        LOGF_W("SSH", "Keep-alive failed: %d", rc);
    }
}

bool SSHTunnel::checkConnection() {
    if (!session || !sshClient.connected()) {
        return false;
    }

    // Additional connection health checks could be added here
    return true;
}

void SSHTunnel::handleReconnection() {
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        LOG_E("SSH", "Max reconnection attempts reached");
        state = TUNNEL_ERROR;
        return;
    }

    unsigned long now = millis();
    if (now - lastConnectionAttempt < RECONNECT_DELAY_MS) {
        return; // Wait before retry
    }

    LOG_I("SSH", "Attempting reconnection...");
    disconnect();
    reconnectAttempts++;

    if (connect()) {
        LOG_I("SSH", "Reconnection successful");
        reconnectAttempts = 0;
    }
}

TunnelState SSHTunnel::getState() {
    return state;
}

String SSHTunnel::getStateString() {
    switch (state) {
        case TUNNEL_DISCONNECTED: return "Disconnected";
        case TUNNEL_CONNECTING:   return "Connecting";
        case TUNNEL_CONNECTED:    return "Connected";
        case TUNNEL_ERROR:        return "Error";
        default:                  return "Unknown";
    }
}

unsigned long SSHTunnel::getBytesReceived() {
    return bytesReceived;
}

unsigned long SSHTunnel::getBytesSent() {
    return bytesSent;
}

int SSHTunnel::getActiveChannels() {
    int count = 0;
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (channels[i].active) count++;
    }
    return count;
}


