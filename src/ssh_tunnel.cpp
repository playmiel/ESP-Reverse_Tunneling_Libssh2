#include "ssh_tunnel.h"
#include "network_optimizations.h"
#include "memory_fixes.h"
#include "lwip/sockets.h"

// Define buffer size for data chunks
#define SSH_BUFFER_SIZE 1024

// Optimized (reduced) flow-control thresholds to limit accumulation and improve backpressure
#undef HIGH_WATER_LOCAL
#undef LOW_WATER_LOCAL
#define HIGH_WATER_LOCAL (3 * 1024)      // 3KB - proactively pause local socket reads
#define LOW_WATER_LOCAL  (2 * 1024)      // 2KB - resume local socket reads
#define CRITICAL_WATER_LOCAL (4 * 1024)  // 4KB - hard stop local socket reads

// SSH write parameters now defined as static constexpr members of SSHTunnel (see header)

// Fixed buffer (unchanged) + channel integrity threshold
#define FIXED_BUFFER_SIZE (8 * 1024)
#define MAX_QUEUED_BYTES (32 * 1024)

// Health/recovery tuning (reduce noisy recoveries and WARN spam)
#ifndef HEALTH_UNHEALTHY_THRESHOLD
#define HEALTH_UNHEALTHY_THRESHOLD 3     // consecutive unhealthy checks before hard recovery
#endif
#ifndef RECOVERY_COOLDOWN_MS
#define RECOVERY_COOLDOWN_MS 3000        // min delay between hard recoveries per channel
#endif
#ifndef HEALTH_WARN_THROTTLE_MS
#define HEALTH_WARN_THROTTLE_MS 5000     // rate-limit health WARN logs per channel
#endif

SSHTunnel::SSHTunnel()
    : session(nullptr), listener(nullptr), socketfd(-1),
      state(TUNNEL_DISCONNECTED), lastKeepAlive(0), lastConnectionAttempt(0),
  reconnectAttempts(0), bytesReceived(0), bytesSent(0), droppedBytes(0),
      channels(nullptr), rxBuffer(nullptr), txBuffer(nullptr),
      tunnelMutex(nullptr), statsMutex(nullptr), pendingConnectionsMutex(nullptr), 
      config(&globalSSHConfig), dataProcessingTask(nullptr), 
      dataProcessingSemaphore(nullptr), dataProcessingTaskRunning(false) {

  // OPTIMIZED: Use mutexes instead of binary semaphores for better performance
  tunnelMutex = xSemaphoreCreateMutex();
  statsMutex = xSemaphoreCreateMutex();
  pendingConnectionsMutex = xSemaphoreCreateMutex();
  dataProcessingSemaphore = xSemaphoreCreateBinary();
  
  if (tunnelMutex == NULL || statsMutex == NULL || pendingConnectionsMutex == NULL || dataProcessingSemaphore == NULL) {
    LOG_E("SSH", "Failed to create tunnel mutexes");
  }
}

SSHTunnel::~SSHTunnel() {
  // Stop the data processing task
  stopDataProcessingTask();
  
  disconnect();
  
  // Free semaphores
  SAFE_DELETE_SEMAPHORE(tunnelMutex);
  SAFE_DELETE_SEMAPHORE(statsMutex);
  SAFE_DELETE_SEMAPHORE(pendingConnectionsMutex);
  SAFE_DELETE_SEMAPHORE(dataProcessingSemaphore);
  
  // Clean pending connections
  for (auto& pending : pendingConnections) {
    if (pending.channel) {
      libssh2_channel_close(pending.channel);
      libssh2_channel_free(pending.channel);
    }
  }
  pendingConnections.clear();
  
  // Free dynamically allocated memory with ring buffers
  if (channels != nullptr) {
    for (int i = 0; i < config->getConnectionConfig().maxChannels; i++) {
  // OPTIMIZED: Clean unified buffers
      if (channels[i].sshToLocalBuffer) {
        delete channels[i].sshToLocalBuffer;
        channels[i].sshToLocalBuffer = nullptr;
      }
      if (channels[i].localToSshBuffer) {
        delete channels[i].localToSshBuffer;
        channels[i].localToSshBuffer = nullptr;
      }
      
      SAFE_DELETE_SEMAPHORE(channels[i].readMutex);
      SAFE_DELETE_SEMAPHORE(channels[i].writeMutex);
    }
    SAFE_FREE(channels);
  }
  
  SAFE_FREE(rxBuffer);
  SAFE_FREE(txBuffer);
}

bool SSHTunnel::init() {
  if (!lockTunnel()) {
    LOG_E("SSH", "Failed to lock tunnel for initialization");
    return false;
  }
  
  // Validate configuration
  if (!config->validateConfiguration()) {
    LOG_E("SSH", "Invalid configuration");
    unlockTunnel();
    return false;
  }
  
  // Allocate memory for channels with validation
  int maxChannels = config->getConnectionConfig().maxChannels;
  size_t channelsSize = sizeof(TunnelChannel) * maxChannels;
  channels = (TunnelChannel*)safeMalloc(channelsSize, "SSH_CHANNELS");
  if (channels == nullptr) {
    LOG_E("SSH", "Failed to allocate memory for channels");
    unlockTunnel();
    return false;
  }
  
  // Initialize channels with ring buffers
  for (int i = 0; i < maxChannels; i++) {
    channels[i].channel = nullptr;
    channels[i].localSocket = -1;
    channels[i].active = false;
    channels[i].lastActivity = 0;
    channels[i].pendingBytes = 0;
    channels[i].flowControlPaused = false;
    
  // Initialize new reliability-related fields
    channels[i].totalBytesReceived = 0;
    channels[i].totalBytesSent = 0;
    channels[i].lastSuccessfulWrite = 0;
    channels[i].lastSuccessfulRead = 0;
    channels[i].gracefulClosing = false;
    channels[i].consecutiveErrors = 0;
  channels[i].eagainErrors = 0; // NEW: Separate counter for EAGAIN
    channels[i].readMutexFailures = 0; // FIXED: Initialize new failure counters
    channels[i].writeMutexFailures = 0;
    channels[i].queuedBytesToLocal = 0;
    channels[i].queuedBytesToRemote = 0;
    channels[i].lostWriteChunks = 0;
  channels[i].bytesDropped = 0;
    
  // NEW: Initialize large-transfer detection variables
    channels[i].largeTransferInProgress = false;
    channels[i].transferStartTime = 0;
    channels[i].transferredBytes = 0;
    channels[i].peakBytesPerSecond = 0;
  channels[i].socketRecvErrors = 0;
  channels[i].fatalCryptoErrors = 0;
  channels[i].lastWriteErrorMs = 0;
  channels[i].lastErrorDetailLogMs = 0;
    
  // OPTIMIZED: Create unified buffers (simpler & efficient)
    char ringName[32];
    
  // Unified buffer for SSH->Local (FIXED_BUFFER_SIZE = 8KB)
    snprintf(ringName, sizeof(ringName), "CH%d_SSH2LOC", i);
    channels[i].sshToLocalBuffer = new DataRingBuffer(FIXED_BUFFER_SIZE, ringName);
    
  // Unified buffer for Local->SSH (FIXED_BUFFER_SIZE = 8KB)
    snprintf(ringName, sizeof(ringName), "CH%d_LOC2SSH", i);
    channels[i].localToSshBuffer = new DataRingBuffer(FIXED_BUFFER_SIZE, ringName);
    
    if (!channels[i].sshToLocalBuffer || !channels[i].localToSshBuffer) {
      LOGF_E("SSH", "Failed to create unified buffers for channel %d", i);
      unlockTunnel();
      return false;
    }
    
  // OPTIMIZED: Create mutexes instead of binary semaphores
    channels[i].readMutex = xSemaphoreCreateMutex();
    channels[i].writeMutex = xSemaphoreCreateMutex();
    
    if (channels[i].readMutex == NULL || channels[i].writeMutex == NULL) {
      LOGF_E("SSH", "Failed to create mutexes for channel %d", i);
      unlockTunnel();
      return false;
    }

    // NEW: init deferred residual buffers (partial enqueue protection)
    channels[i].deferredToLocal = nullptr;
    channels[i].deferredToLocalSize = 0;
    channels[i].deferredToLocalOffset = 0;
    channels[i].deferredToRemote = nullptr;
    channels[i].deferredToRemoteSize = 0;
    channels[i].deferredToRemoteOffset = 0;
  }
  
  // Allocate RX/TX buffers (use fixed size)
  rxBuffer = (uint8_t*)safeMalloc(FIXED_BUFFER_SIZE, "SSH_RX_BUFFER");
  txBuffer = (uint8_t*)safeMalloc(FIXED_BUFFER_SIZE, "SSH_TX_BUFFER");
  
  if (rxBuffer == nullptr || txBuffer == nullptr) {
    LOG_E("SSH", "Failed to allocate memory for buffers");
    unlockTunnel();
    return false;
  }
  
  // Initialize libssh2
  int rc = libssh2_init(0);
  if (rc != 0) {
    LOGF_E("SSH", "libssh2 initialization failed: %d", rc);
    unlockTunnel();
    return false;
  }

  // NEW: Start dedicated data processing task
  if (!startDataProcessingTask()) {
    LOG_E("SSH", "Failed to start data processing task");
    unlockTunnel();
    return false;
  }

  LOG_I("SSH", "SSH tunnel initialized with optimized buffers and dedicated task");
  config->printConfiguration();
  
  unlockTunnel();
  return true;
}

bool SSHTunnel::connectSSH() {
  if (state == TUNNEL_CONNECTING) {
    return false; // Already attempting connection
  }

  unsigned long now = millis();
  int reconnectDelay = config->getConnectionConfig().reconnectDelayMs;
  if (now - lastConnectionAttempt < reconnectDelay) {
    return false; // Too soon since last attempt
  }

  lastConnectionAttempt = now;
  state = TUNNEL_CONNECTING;

  LOG_I("SSH", "Attempting SSH connection...");

  if (!initializeSSH()) {
    LOG_E("SSH", "SSH initialization failed");
    state = TUNNEL_ERROR;
    close(socketfd);
    socketfd = -1;
    return false;
  }

  if (!authenticateSSH()) {
    LOG_E("SSH", "SSH authentication failed");
    state = TUNNEL_ERROR;
    cleanupSSH();
    close(socketfd);
    socketfd = -1;
    return false;
  }

  if (!createReverseTunnel()) {
    LOG_E("SSH", "Failed to create reverse tunnel");
    state = TUNNEL_ERROR;
    cleanupSSH();
    close(socketfd);
    socketfd = -1;
    return false;
  }

  state = TUNNEL_CONNECTED;

  reconnectAttempts = 0;
  lastKeepAlive = millis();

  TunnelConfig tunnelConf = config->getTunnelConfig();
  LOGF_I("SSH", "Reverse tunnel established: %s:%d -> %s:%d", 
         tunnelConf.remoteBindHost.c_str(), tunnelConf.remoteBindPort,
         tunnelConf.localHost.c_str(), tunnelConf.localPort);

  return true;
}

void SSHTunnel::disconnect() {
  LOG_I("SSH", "Disconnecting SSH tunnel...");

  // Close all channels with protection to avoid NULL pointer issues
  if (channels != nullptr) {
    int maxChannels = config->getConnectionConfig().maxChannels;
    for (int i = 0; i < maxChannels; i++) {
      if (channels[i].active) {
        closeChannel(i);
      }
    }
  }

  cleanupSSH();
  if (socketfd >= 0) {
    close(socketfd);
    socketfd = -1;
  }
  state = TUNNEL_DISCONNECTED;

  LOG_I("SSH", "SSH tunnel disconnected");
}

bool SSHTunnel::isConnected() { return state == TUNNEL_CONNECTED; }

void SSHTunnel::loop() {
  unsigned long now = millis();

  // Handle reconnection if needed
  if (state == TUNNEL_ERROR ||
      (state == TUNNEL_CONNECTED && !checkConnection())) {
    handleReconnection();
    return;
  }

  if (state != TUNNEL_CONNECTED) {
    return;
  }

  // Send keep-alive
  int keepAliveInterval = config->getConnectionConfig().keepAliveIntervalSec;
  if (now - lastKeepAlive > keepAliveInterval * 1000) {
    sendKeepAlive();
    lastKeepAlive = now;
  }

  // OPTIMIZED: Reduce log frequency in the hot loop
  // Periodic statistics (every 5 minutes instead of 2)
  static unsigned long lastStatsTime = 0;
  if (now - lastStatsTime > 300000) { // 5 minutes
    printChannelStatistics();
    lastStatsTime = now;
  }

  // NEW: Deadlock check every 30 seconds (reduced frequency)
  static unsigned long lastDeadlockCheck = 0;
  if (now - lastDeadlockCheck > 30000) { // 30 secondes
    checkAndRecoverDeadlocks();
    lastDeadlockCheck = now;
  }

  // Handle new connections
  handleNewConnection();
  
  // NEW: Process pending connections only if no large transfer is active
  if (!isLargeTransferActive()) {
    processPendingConnections();
  }

  // Handle data for existing channels (optimized with fewer logs)
  int maxChannels = config->getConnectionConfig().maxChannels;
  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active) {
  // OPTIMIZED: Delegate heavy processing to the dedicated task
  // Signal the processing task there is work
      if (dataProcessingSemaphore) {
        xSemaphoreGive(dataProcessingSemaphore);
      }
      
  // Lightweight processing in the main loop
      handleChannelData(i);
    }
  }

  // Cleanup inactive channels
  cleanupInactiveChannels();
  
  // OPTIMIZED: Slightly increase delay to reduce CPU contention
  vTaskDelay(pdMS_TO_TICKS(10)); // 10ms au lieu de 5ms
}

bool SSHTunnel::initializeSSH() {
  struct sockaddr_in sin;
  int rc = 0;
  rc = libssh2_init(0);
  if (rc != 0) {
    LOGF_E("SSH", "libssh2 initialization failed: %d", rc);

    return false; // Initialization failed
  }
  socketfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socketfd == -1) {
    LOGF_E("SSH", "Error opening socket");
    return false;
  }

  // Optimiser le socket SSH pour de meilleures performances
  if (!NetworkOptimizer::optimizeSSHSocket(socketfd)) {
    LOGF_W("SSH", "Warning: Could not apply all socket optimizations");
  }

  // Utiliser la configuration SSH
  const SSHServerConfig& sshConfig = config->getSSHConfig();
  
  sin.sin_family = AF_INET;
  struct hostent *he = gethostbyname(sshConfig.host.c_str());
  if (he == nullptr) {
    LOGF_E("Invalid remote hostname: %s\n", sshConfig.host.c_str());
    close(socketfd);
    return false;
  }
  memcpy(&sin.sin_addr, he->h_addr_list[0], he->h_length);
  sin.sin_port = htons(sshConfig.port); /* SSH port */
  if (connect(socketfd, (struct sockaddr *)(&sin),
              sizeof(struct sockaddr_in)) != 0) {
    LOGF_E("SSH", "Failed to connect!");
    close(socketfd);
    return false;
  }
  /* Create a session instance */
  session = libssh2_session_init();
  if (!session) {
    LOG_E("SSH", "Could not initialize the SSH session!");
    return false;
  }

  /* Start it up. This will trade welcome banners, exchange keys,
   * and setup crypto, compression, and MAC layers */
  rc = libssh2_session_handshake(session, socketfd);
  if (rc) {
    LOGF_E("SSH", "Error when starting up SSH session: %d", rc);
    return false;
  }

  // libssh2_trace(session, LIBSSH2_TRACE_SOCKET | LIBSSH2_TRACE_ERROR);

  /* At this point we haven't yet authenticated. The first thing to do
   * is check the hostkey's fingerprint against our known hosts */
  if (!verifyHostKey()) {
    LOG_E("SSH", "Host key verification failed");
    return false;
  }

  LOG_I("SSH", "SSH handshake completed");
  return true;
}

bool SSHTunnel::verifyHostKey() {
  const SSHServerConfig& sshConfig = config->getSSHConfig();
  
  // If verification disabled, accept any host key
  if (!sshConfig.verifyHostKey) {
    LOG_W("SSH", "Host key verification disabled - connection accepted without verification");
    return true;
  }
  
  // Get server host key
  size_t host_key_len;
  int host_key_type;
  const char* host_key = libssh2_session_hostkey(session, &host_key_len, &host_key_type);
  
  if (!host_key) {
    LOG_E("SSH", "Failed to get host key from server");
    return false;
  }
  
  // Get SHA256 fingerprint
  const char *fingerprint_sha256 = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256);
  if (!fingerprint_sha256) {
    LOG_E("SSH", "Failed to get host key fingerprint");
    return false;
  }
  
  // Convert fingerprint to hexadecimal string
  String currentFingerprint = "";
  for (int i = 0; i < 32; i++) {  // SHA256 = 32 bytes
    char hex[3];
    sprintf(hex, "%02x", (unsigned char)fingerprint_sha256[i]);
    currentFingerprint += hex;
  }
  
  // Validate key type if specified
  String keyTypeStr = "";
  switch (host_key_type) {
    case LIBSSH2_HOSTKEY_TYPE_RSA:
      keyTypeStr = "ssh-rsa";
      break;
    case LIBSSH2_HOSTKEY_TYPE_DSS:
      keyTypeStr = "ssh-dss"; 
      break;
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
      keyTypeStr = "ecdsa-sha2-nistp256";
      break;
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
      keyTypeStr = "ecdsa-sha2-nistp384";
      break;
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:
      keyTypeStr = "ecdsa-sha2-nistp521";
      break;
    case LIBSSH2_HOSTKEY_TYPE_ED25519:
      keyTypeStr = "ssh-ed25519";
      break;
    default:
      keyTypeStr = "unknown";
      break;
  }
  
  LOGF_I("SSH", "Server host key: %s", keyTypeStr.c_str());
  LOGF_I("SSH", "Server fingerprint (SHA256): %s", currentFingerprint.c_str());
  
  // Validate key type again if user provided a filter
  if (sshConfig.hostKeyType.length() > 0 && sshConfig.hostKeyType != keyTypeStr) {
    LOGF_E("SSH", "Host key type mismatch! Expected: %s, Got: %s", 
           sshConfig.hostKeyType.c_str(), keyTypeStr.c_str());
    return false;
  }
  
  // Verify fingerprint
  if (sshConfig.expectedHostKeyFingerprint.length() == 0) {
    LOG_W("SSH", "No expected fingerprint configured - accepting and storing current fingerprint");
    LOGF_I("SSH", "Store this fingerprint in your configuration: %s", currentFingerprint.c_str());
    return true;
  }
  
  // Normalize fingerprints (remove spaces & colons, lowercase)
  String expectedFP = sshConfig.expectedHostKeyFingerprint;
  expectedFP.toLowerCase();
  expectedFP.replace(" ", "");
  expectedFP.replace(":", "");
  
  String currentFP = currentFingerprint;
  currentFP.toLowerCase();
  
  if (expectedFP != currentFP) {
    LOG_E("SSH", "HOST KEY VERIFICATION FAILED!");
    LOG_E("SSH", "This could indicate a Man-in-the-Middle attack!");
    LOGF_E("SSH", "Expected: %s", expectedFP.c_str());
    LOGF_E("SSH", "Got:      %s", currentFP.c_str());
    LOGF_E("SSH", "Key type: %s", keyTypeStr.c_str());
    return false;
  }
  
  LOG_I("SSH", "Host key verification successful");
  return true;
}

bool SSHTunnel::authenticateSSH() {
  // Utiliser la configuration SSH
  const SSHServerConfig& sshConfig = config->getSSHConfig();
  
  /* check what authentication methods are available */
  char *userauthlist =
      libssh2_userauth_list(session, sshConfig.username.c_str(), sshConfig.username.length());
  LOGF_I("SSH", "Authentication methods: %s", userauthlist);

  int auth = 0;
#define AUTH_PASSWORD 1
#define AUTH_PUBLICKEY 2

  if (strstr(userauthlist, "password"))
    auth |= AUTH_PASSWORD;
  if (strstr(userauthlist, "publickey"))
    auth |= AUTH_PUBLICKEY;

  if (sshConfig.useSSHKey) {
    auth = AUTH_PUBLICKEY;
  } else {
    auth = AUTH_PASSWORD;
  }

  if (auth & AUTH_PASSWORD) {
    if (libssh2_userauth_password(session, sshConfig.username.c_str(), sshConfig.password.c_str())) {
      LOG_E("SSH", "Authentication by password failed");
      return false;
    }
    LOG_I("SSH", "Authentication by password succeeded");
  } else if (auth & AUTH_PUBLICKEY) {
  // Diagnose keys before authentication
    config->diagnoseSSHKeys();
    
  // Check if keys are already loaded in memory
    if (sshConfig.privateKeyData.length() > 0 && sshConfig.publicKeyData.length() > 0) {
  // Validate keys before attempting authentication
      if (!config->validateSSHKeys()) {
        LOG_E("SSH", "SSH keys validation failed");
        return false;
      }
      
  // Use libssh2_userauth_publickey_frommemory
      LOGF_I("SSH", "Authenticating with keys from memory (private: %d bytes, public: %d bytes)", 
             sshConfig.privateKeyData.length(), sshConfig.publicKeyData.length());
      
      const char* passphrase = sshConfig.password.length() > 0 ? sshConfig.password.c_str() : nullptr;
      
      LOGF_D("SSH", "Public key first 50 chars: %.50s", sshConfig.publicKeyData.c_str());
      LOGF_D("SSH", "Private key first 50 chars: %.50s", sshConfig.privateKeyData.c_str());
      LOGF_D("SSH", "Using passphrase: %s", passphrase ? "yes" : "no");
      
      int auth_result = libssh2_userauth_publickey_frommemory(session, 
                                                sshConfig.username.c_str(),
                                                sshConfig.username.length(),
                                                sshConfig.publicKeyData.c_str(),
                                                sshConfig.publicKeyData.length(),
                                                sshConfig.privateKeyData.c_str(),
                                                sshConfig.privateKeyData.length(),
                                                passphrase);
      if (auth_result) {
        char *errmsg;
        int errlen;
        libssh2_session_last_error(session, &errmsg, &errlen, 0);
        LOGF_E("SSH", "Authentication by public key from memory failed! Error code: %d, Message: %s", auth_result, errmsg ? errmsg : "Unknown");
        
  // Retry with explicit empty passphrase
        LOGF_I("SSH", "Retrying with empty passphrase...");
        auth_result = libssh2_userauth_publickey_frommemory(session, 
                                                  sshConfig.username.c_str(),
                                                  sshConfig.username.length(),
                                                  sshConfig.publicKeyData.c_str(),
                                                  sshConfig.publicKeyData.length(),
                                                  sshConfig.privateKeyData.c_str(),
                                                  sshConfig.privateKeyData.length(),
                                                  "");
        if (auth_result) {
          libssh2_session_last_error(session, &errmsg, &errlen, 0);
          LOGF_E("SSH", "Retry with empty passphrase also failed! Error: %d, Message: %s", auth_result, errmsg ? errmsg : "Unknown");
          
          // Final attempt: try NULL instead of empty string
          LOGF_I("SSH", "Final retry with NULL passphrase...");
          auth_result = libssh2_userauth_publickey_frommemory(session, 
                                                    sshConfig.username.c_str(),
                                                    sshConfig.username.length(),
                                                    sshConfig.publicKeyData.c_str(),
                                                    sshConfig.publicKeyData.length(),
                                                    sshConfig.privateKeyData.c_str(),
                                                    sshConfig.privateKeyData.length(),
                                                    NULL);
          if (auth_result) {
            libssh2_session_last_error(session, &errmsg, &errlen, 0);
            LOGF_E("SSH", "All authentication attempts failed! Final error: %d, Message: %s", auth_result, errmsg ? errmsg : "Unknown");
            
            // Info: supported formats hint
            LOG_W("SSH", "Note: Your private key is in OpenSSH format. Consider converting to PEM format:");
            LOG_W("SSH", "ssh-keygen -p -m PEM -f your_key");
            return false;
          } else {
            LOG_I("SSH", "Authentication succeeded with NULL passphrase");
          }
        } else {
          LOG_I("SSH", "Authentication succeeded with empty passphrase");
        }
      }
      LOG_I("SSH", "Authentication by public key from memory succeeded");
    } else {
  // Fallback to file-based method (compatibility)
      LOG_W("SSH", "SSH keys not available in memory, falling back to file-based authentication");
      String keyfile1_str = sshConfig.privateKeyPath + ".pub";
      const char *keyfile1 = keyfile1_str.c_str();
      const char *keyfile2 = sshConfig.privateKeyPath.c_str();
      if (libssh2_userauth_publickey_fromfile(session, sshConfig.username.c_str(), keyfile1,
                                              keyfile2, sshConfig.password.c_str())) {
        LOG_E("SSH", "Authentication by public key from file failed!");
        return false;
      }
      LOG_I("SSH", "Authentication by public key from file succeeded");
    }
  } else {
    LOG_E("SSH", "No supported authentication methods found!");
    return false;
  }

  return true;
}

bool SSHTunnel::createReverseTunnel() {
  int bound_port;
  int maxlisten = 10; // Max number of connections to listen for
  
  // Use runtime configuration instead of hardcoded constants
  const TunnelConfig& tunnelConfig = config->getTunnelConfig();
  int ssh_port = tunnelConfig.remoteBindPort;
  const char* bind_host = tunnelConfig.remoteBindHost.c_str();
  
  do {
    listener = libssh2_channel_forward_listen_ex(
        session, bind_host, ssh_port, &bound_port, maxlisten);
    if (!listener) {
      vTaskDelay(pdMS_TO_TICKS(10));
    }
  } while (!listener);

  if (!listener) {
    LOG_E("SSH", "Failed to create reverse tunnel listener");
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
  if (!listener)
    return false;

  LIBSSH2_CHANNEL *channel = libssh2_channel_forward_accept(listener);

  if (!channel) {
    return false; // No new connection or error
  }

  // NEW: Decide whether to accept connection (queue system currently disabled)
  if (!shouldAcceptNewConnection()) {
    LOGF_W("SSH", "All channels busy - rejecting new connection");
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);
    return false; // Rejeter directement au lieu de mettre en queue
  }

  // Find available channel slot with aggressive reuse
  int channelIndex = -1;
  int maxChannels = config->getConnectionConfig().maxChannels;
  unsigned long now = millis();
  
  // First pass: search for a truly free channel
  for (int i = 0; i < maxChannels; i++) {
    LOGF_D("SSH", "Trying to open new channel slot %d (active=%d)", i, channels[i].active);
    if (!channels[i].active) {
      channelIndex = i;
      LOGF_I("SSH", "Channel slot %d is free and will be used", i);
      break;
    }
  }

  // If none free, look for long inactive channels to recycle
  if (channelIndex == -1) {
    for (int i = 0; i < maxChannels; i++) {
  if (channels[i].active && (now - channels[i].lastActivity > 30000)) { // 30 seconds inactivity
        LOGF_I("SSH", "Recycling inactive channel %d for new connection", i);
  closeChannel(i); // Closes and releases the channel
        channelIndex = i;
        LOGF_I("SSH", "Channel slot %d reused after cleanup", i);
        break;
      }
    }
  }

  if (channelIndex == -1) {
    LOGF_W("SSH", "No available channel slots (active: %d/%d), closing new connection", 
           getActiveChannels(), maxChannels);
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);
    return false;
  }

  // Create socket and connect to local endpoint
  int localSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (localSocket < 0) {
    LOG_E("SSH", "Failed to create local socket");
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);
    return false;
  }

  // Use config for local endpoint
  const TunnelConfig& tunnelConfig = config->getTunnelConfig();
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(tunnelConfig.localPort);
  inet_pton(AF_INET, tunnelConfig.localHost.c_str(), &addr.sin_addr);

  if (::connect(localSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOGF_E("SSH", "Failed to connect to local endpoint %s:%d", 
           tunnelConfig.localHost.c_str(), tunnelConfig.localPort);
    close(localSocket);
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);
    return false;
  }

  // Optimize local socket for performance
  if (!NetworkOptimizer::optimizeSocket(localSocket)) {
    LOGF_W("SSH", "Warning: Could not optimize local socket for channel %d", channelIndex);
  }

  // Set socket non-blocking
  int flags = fcntl(localSocket, F_GETFL, 0);
  fcntl(localSocket, F_SETFL, flags | O_NONBLOCK);

  // Set up channel
  channels[channelIndex].channel = channel;
  channels[channelIndex].localSocket = localSocket;
  channels[channelIndex].active = true;
  channels[channelIndex].lastActivity = millis();
  channels[channelIndex].pendingBytes = 0;
  channels[channelIndex].flowControlPaused = false;
  
  // NEW: Initialize large transfer detection variables for this channel
  channels[channelIndex].largeTransferInProgress = false;
  channels[channelIndex].transferStartTime = millis();
  channels[channelIndex].transferredBytes = 0;
  channels[channelIndex].peakBytesPerSecond = 0;

  // Health tracking init
  channels[channelIndex].healthUnhealthyCount = 0;
  channels[channelIndex].lastHardRecoveryMs = 0;
  channels[channelIndex].lastHealthWarnMs = 0;

  libssh2_channel_set_blocking(channel, 0);

  LOGF_I("SSH", "New tunnel connection established (channel %d)", channelIndex);
  return true;
}

void SSHTunnel::handleChannelData(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active || !ch.channel || ch.localSocket < 0) {
    return;
  }

  unsigned long now = millis();

  // Check channel health before processing data (with hysteresis and cooldown)
  if (!isChannelHealthy(channelIndex)) {
    ch.healthUnhealthyCount++;
    // Prefer a gentle approach first
    if (ch.healthUnhealthyCount < HEALTH_UNHEALTHY_THRESHOLD) {
      if (now - ch.lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
        LOGF_D("SSH", "Channel %d: Unhealthy #%d -> attempting graceful recovery",
               channelIndex, ch.healthUnhealthyCount);
        ch.lastHealthWarnMs = now;
      }
      gracefulRecoverChannel(channelIndex);
    } else {
      // Only allow a hard recovery after cooldown
      if (now - ch.lastHardRecoveryMs > RECOVERY_COOLDOWN_MS) {
        if (now - ch.lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
          LOGF_W("SSH", "Channel %d: Unhealthy threshold reached -> hard recovery", channelIndex);
          ch.lastHealthWarnMs = now;
        }
        recoverChannel(channelIndex);
        ch.lastHardRecoveryMs = now;
        ch.healthUnhealthyCount = 0; // reset after a hard attempt
      } else {
        if (now - ch.lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
          LOGF_I("SSH", "Channel %d: Skipping hard recovery (cooldown)", channelIndex);
          ch.lastHealthWarnMs = now;
        }
      }
    }

    // Verify if recovery succeeded
    if (!isChannelHealthy(channelIndex)) {
      LOGF_E("SSH", "Channel %d: Recovery failed, closing channel", channelIndex);
      closeChannel(channelIndex);
      return;
    } else {
      if (now - ch.lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
        LOGF_I("SSH", "Channel %d: Recovery successful, continuing", channelIndex);
        ch.lastHealthWarnMs = now;
      }
    }
  }

  // PROTECTION: Avoid excessive mutex contention
  static unsigned long lastProcessTime[10] = {0}; // Assumant max 10 canaux
  if (channelIndex < 10 && (now - lastProcessTime[channelIndex]) < 5) {
  return; // Skip if processed too recently
  }
  lastProcessTime[channelIndex] = now;

  // First process pending buffered data to avoid accumulation
  processPendingData(channelIndex);

  // SSH -> Local (read from SSH channel and write to local socket)
  bool readSuccess = processChannelRead(channelIndex);
  
  // Local -> SSH (read from local socket and write to SSH channel)
  bool writeSuccess = processChannelWrite(channelIndex);

  // NEW: Detect large transfers based on activity
  if (readSuccess || writeSuccess) {
    detectLargeTransfer(channelIndex);
  }

  // Update activity & reset errors on successful traffic
  if (readSuccess || writeSuccess) {
    ch.lastActivity = now;
    ch.consecutiveErrors = 0; // Reset errors after success
    ch.healthUnhealthyCount = 0; // Healthy traffic observed
  }

  // Check if channel should be gracefully closed
  if (ch.gracefulClosing) {
  // Force processing of pending data before closing
    processPendingData(channelIndex);
    
  // Check if unified buffers are fully drained
    bool allEmpty = (ch.sshToLocalBuffer ? ch.sshToLocalBuffer->empty() : true) && 
                   (ch.localToSshBuffer ? ch.localToSshBuffer->empty() : true);
    
    if (allEmpty) {
      LOGF_I("SSH", "Channel %d: Graceful close completed - all buffers empty", channelIndex);
      closeChannel(channelIndex);
    } else {
  // Log unified buffer state for diagnostics
      LOGF_D("SSH", "Channel %d: Graceful close waiting - buffers: ssh2local=%zu, local2ssh=%zu", 
             channelIndex, 
             ch.sshToLocalBuffer ? ch.sshToLocalBuffer->size() : 0,
             ch.localToSshBuffer ? ch.localToSshBuffer->size() : 0);
    }
  }
}

void SSHTunnel::closeChannel(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active)
    return;

  unsigned long sessionDuration = millis() - ch.lastActivity;
  
  // Detailed log for debugging with extended statistics
  LOGF_I("SSH", "Closing channel %d (session: %lums, rx: %d bytes, tx: %d bytes, errors: %d)", 
         channelIndex, sessionDuration, ch.totalBytesReceived, ch.totalBytesSent, ch.consecutiveErrors);

  // FIX: Force release of stuck mutexes BEFORE clearing buffers (avoids indefinite block after connection reset)
  safeRetryMutexAccess(channelIndex); // FIXED: Use safe version instead

  // Flush pending data before closing
  flushPendingData(channelIndex);

  if (ch.channel) {
    libssh2_channel_close(ch.channel);
    libssh2_channel_free(ch.channel);
    ch.channel = nullptr;
  }

  if (ch.localSocket >= 0) {
  // Atomic protection: mark socket as closed before actual shutdown
    int socketToClose = ch.localSocket;
  ch.localSocket = -1; // Prevent race conditions
    
  // Clean shutdown
    shutdown(socketToClose, SHUT_RDWR);
    vTaskDelay(pdMS_TO_TICKS(10)); // Laisser le temps aux threads de voir le changement
    close(socketToClose);
    
    LOGF_D("SSH", "Channel %d: Local socket %d closed safely", channelIndex, socketToClose);
  }

  // Full reset of channel state for reuse
  ch.active = false;
  ch.lastActivity = 0;
  ch.pendingBytes = 0;
  ch.flowControlPaused = false;
  ch.totalBytesReceived = 0;
  ch.totalBytesSent = 0;
  ch.lastSuccessfulWrite = 0;
  ch.lastSuccessfulRead = 0;
  ch.gracefulClosing = false;
  ch.consecutiveErrors = 0;
  
  // OPTIMIZED: Reset large transfer detection and EAGAIN counters
  ch.largeTransferInProgress = false;
  ch.transferStartTime = 0;
  ch.transferredBytes = 0;
  ch.peakBytesPerSecond = 0;
  ch.eagainErrors = 0;
  ch.healthUnhealthyCount = 0;
  ch.lastHardRecoveryMs = 0;
  ch.lastHealthWarnMs = 0;
  
  // OPTIMIZED: Clear unified buffers
  if (ch.sshToLocalBuffer) {
    ch.sshToLocalBuffer->clear();
    ch.queuedBytesToLocal = 0;
  }
  if (ch.localToSshBuffer) {
    ch.localToSshBuffer->clear();
    ch.queuedBytesToRemote = 0;
  }
  
  ch.lostWriteChunks = 0;

  // Free deferred buffers if any
  if (ch.deferredToLocal) { SAFE_FREE(ch.deferredToLocal); ch.deferredToLocal=nullptr; }
  ch.deferredToLocalSize = ch.deferredToLocalOffset = 0;
  if (ch.deferredToRemote) { SAFE_FREE(ch.deferredToRemote); ch.deferredToRemote=nullptr; }
  ch.deferredToRemoteSize = ch.deferredToRemoteOffset = 0;

  LOGF_I("SSH", "Channel %d closed and ready for reuse (slot now free)", channelIndex);
}

void SSHTunnel::cleanupInactiveChannels() {
  unsigned long now = millis();
  int maxChannels = config->getConnectionConfig().maxChannels;
  int channelTimeout = config->getConnectionConfig().channelTimeoutMs;
  int activeBefore = getActiveChannels();

  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active) {
      unsigned long timeSinceActivity = now - channels[i].lastActivity;
      
      // NEW: Detect & repair with hysteresis/cooldown to avoid noisy recoveries
      if (!isChannelHealthy(i)) {
        channels[i].healthUnhealthyCount++;
        if (channels[i].healthUnhealthyCount < HEALTH_UNHEALTHY_THRESHOLD) {
          if (now - channels[i].lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
            LOGF_D("SSH", "Channel %d unhealthy (%d) -> graceful recover", i, channels[i].healthUnhealthyCount);
            channels[i].lastHealthWarnMs = now;
          }
          gracefulRecoverChannel(i);
        } else if (now - channels[i].lastHardRecoveryMs > RECOVERY_COOLDOWN_MS) {
          if (now - channels[i].lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
            LOGF_W("SSH", "Channel %d unhealthy threshold -> hard recover", i);
            channels[i].lastHealthWarnMs = now;
          }
          recoverChannel(i);
          channels[i].lastHardRecoveryMs = now;
          channels[i].healthUnhealthyCount = 0;
        }
        // Give the recovered channel a chance
        continue;
      }
      
  // Smarter, less aggressive cleanup decision
      bool shouldClose = false;
      
  // First check if channel is already in graceful closing
      if (channels[i].gracefulClosing) {
  // Force processing of remaining data
        processPendingData(i);
        
  // Allow more time to drain unified buffers
        if ((channels[i].sshToLocalBuffer ? channels[i].sshToLocalBuffer->empty() : true) &&
            (channels[i].localToSshBuffer ? channels[i].localToSshBuffer->empty() : true)) {
          shouldClose = true;
          LOGF_I("SSH", "Channel %d graceful close completed", i);
        } else if (timeSinceActivity > 60000) { // 60 secondes au lieu de 30 pour graceful close
          shouldClose = true;
          LOGF_W("SSH", "Channel %d graceful close timeout - forcing close with pending data", i);
          LOGF_W("SSH", "Channel %d buffers: ssh2local=%zu, local2ssh=%zu", i,
                 channels[i].sshToLocalBuffer ? channels[i].sshToLocalBuffer->size() : 0,
                 channels[i].localToSshBuffer ? channels[i].localToSshBuffer->size() : 0);
        } else {
          // Periodic log of state during graceful close
          static unsigned long lastGracefulLog[16] = {0}; // Pour 16 canaux max
          if (now - lastGracefulLog[i] > 5000) { // Log every 5s
            LOGF_I("SSH", "Channel %d graceful close in progress - buffers: ssh2local=%zu, local2ssh=%zu", i,
                   channels[i].sshToLocalBuffer ? channels[i].sshToLocalBuffer->size() : 0,
                   channels[i].localToSshBuffer ? channels[i].localToSshBuffer->size() : 0);
            lastGracefulLog[i] = now;
          }
        }
      } else {
  // Normal timeout but more tolerant
        if (timeSinceActivity > channelTimeout * 2) { // Double du timeout normal
          shouldClose = true;
          LOGF_W("SSH", "Channel %d timeout after %lums, closing", i, timeSinceActivity);
        }
  // Channels with too many consecutive errors
        else if (channels[i].consecutiveErrors > 10) {
          shouldClose = true;
          LOGF_W("SSH", "Channel %d has too many errors (%d), closing", i, channels[i].consecutiveErrors);
        }
  // Unified buffers too full for too long
        else if (((channels[i].sshToLocalBuffer ? channels[i].sshToLocalBuffer->size() : 0) > 8192 || 
                  (channels[i].localToSshBuffer ? channels[i].localToSshBuffer->size() : 0) > 8192) && 
                 timeSinceActivity > 60000) {
          shouldClose = true;
          LOGF_W("SSH", "Channel %d has full buffers for %lums, closing", i, timeSinceActivity);
        }
  // Stale data in unified buffers (>10 seconds)
        else if (!(channels[i].sshToLocalBuffer ? channels[i].sshToLocalBuffer->empty() : true) || 
                 !(channels[i].localToSshBuffer ? channels[i].localToSshBuffer->empty() : true)) {
          // For unified buffers, process pending data
          if (timeSinceActivity > 10000) {
            LOGF_W("SSH", "Channel %d has old data in buffers, processing", i);
            // Clean old data instead of closing the channel
            processPendingData(i);
          }
        }
      }
      
      if (shouldClose) {
        closeChannel(i);
      }
    }
  }
  
  // Periodic channel state log (every 60 seconds)
  static unsigned long lastLog = 0;
  if (now - lastLog > 60000) {
    int activeAfter = getActiveChannels();
    int totalQueued = 0;
    for (int i = 0; i < maxChannels; i++) {
      if (channels[i].active) {
        totalQueued += (channels[i].sshToLocalBuffer ? channels[i].sshToLocalBuffer->size() : 0) + 
                      (channels[i].localToSshBuffer ? channels[i].localToSshBuffer->size() : 0);
      }
    }
    LOGF_I("SSH", "Channel status: %d active, %d total queued bytes, Dropped=%lu bytes", activeAfter, totalQueued, droppedBytes);
    lastLog = now;
  }
}

void SSHTunnel::printChannelStatistics() {
  static unsigned long lastStatsTime = 0;
  unsigned long now = millis();
  
  // Print stats every 2 minutes
  if (now - lastStatsTime < 120000) return;
  lastStatsTime = now;
  
  int activeCount = 0;
  int flowPausedCount = 0;
  int pendingBytesTotal = 0;
  
  int maxChannels = config->getConnectionConfig().maxChannels;
  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active) {
      activeCount++;
      if (channels[i].flowControlPaused) flowPausedCount++;
      pendingBytesTotal += channels[i].pendingBytes;
    }
  }
  
  LOGF_I("SSH", "Channel Stats: Active=%d/%d, FlowPaused=%d, TotalPending=%d bytes, Dropped=%lu bytes", 
    activeCount, maxChannels, flowPausedCount, pendingBytesTotal, droppedBytes);
  
  // Special alerts
  if (activeCount == maxChannels) {
    LOGF_W("SSH", "WARNING: All channels in use - potential bottleneck");
  }
  if (flowPausedCount > activeCount / 2) {
    LOGF_W("SSH", "WARNING: Many channels flow-paused (%d/%d) - network congestion", 
           flowPausedCount, activeCount);
  }
}


void SSHTunnel::sendKeepAlive() {
  if (!session)
    return;

  int seconds = 0;
  int rc = libssh2_keepalive_send(session, &seconds);
  if (rc == 0) {
    LOGF_D("SSH", "Keep-alive sent, next in %d seconds", seconds);
  } else if (rc != LIBSSH2_ERROR_EAGAIN) {
    LOGF_W("SSH", "Keep-alive failed: %d", rc);
  }
}

bool SSHTunnel::checkConnection() {
  if (!session || socketfd < 0) {
    return false;
  }

  // Check if socket is still valid
  int error = 0;
  socklen_t len = sizeof(error);
  int retval = getsockopt(socketfd, SOL_SOCKET, SO_ERROR, &error, &len);
  if (retval != 0 || error != 0) {
    return false;
  }

  return true;
}

void SSHTunnel::handleReconnection() {
  int maxReconnectAttempts = config->getConnectionConfig().maxReconnectAttempts;
  if (reconnectAttempts >= maxReconnectAttempts) {
    LOG_E("SSH", "Max reconnection attempts reached");
    state = TUNNEL_ERROR;
    return;
  }

  unsigned long now = millis();
  int reconnectDelay = config->getConnectionConfig().reconnectDelayMs;
  if (now - lastConnectionAttempt < reconnectDelay) {
    return; // Wait before retry
  }

  LOG_I("SSH", "Attempting reconnection...");
  disconnect();
  reconnectAttempts++;

  if (connectSSH()) {
    LOG_I("SSH", "Reconnection successful");
    reconnectAttempts = 0;

  } else {
    LOG_E("SSH", "Reconnection failed");

  }
}

TunnelState SSHTunnel::getState() { return state; }

String SSHTunnel::getStateString() {
  switch (state) {
  case TUNNEL_DISCONNECTED:
    return "Disconnected";
  case TUNNEL_CONNECTING:
    return "Connecting";
  case TUNNEL_CONNECTED:
    return "Connected";
  case TUNNEL_ERROR:
    return "Error";
  default:
    return "Unknown";
  }
}

unsigned long SSHTunnel::getBytesReceived() { return bytesReceived; }

unsigned long SSHTunnel::getBytesSent() { return bytesSent; }

unsigned long SSHTunnel::getBytesDropped() { return droppedBytes; }

int SSHTunnel::getActiveChannels() {
  int count = 0;
  int maxChannels = config->getConnectionConfig().maxChannels;
  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active)
      count++;
  }
  return count;
}

int SSHTunnel::socketCallback(LIBSSH2_SESSION *session, libssh2_socket_t fd,
                              void **abstract) {
  // This function can be used to handle socket events if needed
  // For now, we return 0 to indicate no special handling
  return 0;
}
// Semaphore-based protection methods
bool SSHTunnel::lockTunnel() {
  if (tunnelMutex == NULL) {
    return false;
  }
  return xSemaphoreTake(tunnelMutex, portMAX_DELAY) == pdTRUE;
}

void SSHTunnel::unlockTunnel() {
  if (tunnelMutex != NULL) {
    xSemaphoreGive(tunnelMutex);
  }
}

bool SSHTunnel::lockStats() {
  if (statsMutex == NULL) {
    return false;
  }
  return xSemaphoreTake(statsMutex, portMAX_DELAY) == pdTRUE;
}

void SSHTunnel::unlockStats() {
  if (statsMutex != NULL) {
    xSemaphoreGive(statsMutex);
  }
}

// New methods with separate mutexes and short timeout
bool SSHTunnel::lockChannelRead(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) {
    return false;
  }
  
  if (channels[channelIndex].readMutex == NULL) {
    return false;
  }
  
  // MONITORING: Surveiller les tentatives de verrouillage
  unsigned long start = millis();

  // Timeout restored to stable v1.3 value (100ms)
  BaseType_t result = xSemaphoreTake(channels[channelIndex].readMutex, pdMS_TO_TICKS(100));
  unsigned long duration = millis() - start;
  
  if (result != pdTRUE) {
    // Don't log as WARNING to avoid spam - just count
    channels[channelIndex].readMutexFailures++;
    if (channels[channelIndex].readMutexFailures % 50 == 1) { // Log only every 50 times
      LOGF_D("SSH", "Channel %d: Read mutex timeout after %lums (failures=%d)", 
             channelIndex, duration, channels[channelIndex].readMutexFailures);
    }
    return false;
  }
  
  if (duration > 40) { // Seuil réduit 50 -> 40ms et log DEBUG (cache flush)
    LOGF_D("SSH", "Channel %d: READ mutex acquired after %lums (slow)", channelIndex, duration);
  }
  
  return true;
}

void SSHTunnel::unlockChannelRead(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }
  
  if (channels[channelIndex].readMutex != NULL) {
    // Defensive: try to give; if it fails in future, convert to counting log
    xSemaphoreGive(channels[channelIndex].readMutex);
  }
}

bool SSHTunnel::lockChannelWrite(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) {
    return false;
  }
  
  if (channels[channelIndex].writeMutex == NULL) {
    return false;
  }
  
  // MONITORING: Surveiller les tentatives de verrouillage  
  unsigned long start = millis();

  // Timeout restored to stable v1.3 value (100ms)
  BaseType_t result = xSemaphoreTake(channels[channelIndex].writeMutex, pdMS_TO_TICKS(100));
  unsigned long duration = millis() - start;
  
  if (result != pdTRUE) {
    // Don't log as WARNING to avoid spam - just count
    channels[channelIndex].writeMutexFailures++;
    if (channels[channelIndex].writeMutexFailures % 50 == 1) { // Log only every 50 times
      LOGF_D("SSH", "Channel %d: Write mutex timeout after %lums (failures=%d)", 
             channelIndex, duration, channels[channelIndex].writeMutexFailures);
    }
    return false;
  }
  
  if (duration > 40) { // Seuil réduit 50 -> 40ms et log DEBUG
    LOGF_D("SSH", "Channel %d: WRITE mutex acquired after %lums (slow)", channelIndex, duration);
  }
  
  return true;
}

void SSHTunnel::unlockChannelWrite(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }
  
  if (channels[channelIndex].writeMutex != NULL) {
    xSemaphoreGive(channels[channelIndex].writeMutex);
  }
}

// Méthodes de compatibilité (deprecated) - utilisent le writeMutex par défaut
bool SSHTunnel::lockChannel(int channelIndex) {
  return lockChannelWrite(channelIndex);
}

void SSHTunnel::unlockChannel(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }
  
  if (channels[channelIndex].writeMutex != NULL) {
    xSemaphoreGive(channels[channelIndex].writeMutex);
  }
}

// FIXED: Safe method to handle mutex issues without destroying them
void SSHTunnel::safeRetryMutexAccess(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }
  
  TunnelChannel &ch = channels[channelIndex];
  
  // SAFE: Try to acquire without forcing deletion
  bool readOk = false, writeOk = false;
  
  if (ch.readMutex) {
    if (xSemaphoreTake(ch.readMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
      xSemaphoreGive(ch.readMutex);
      readOk = true;
    }
  }
  
  if (ch.writeMutex) {
    if (xSemaphoreTake(ch.writeMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
      xSemaphoreGive(ch.writeMutex);
      writeOk = true;
    }
  }
  
  if (!readOk || !writeOk) {
    // Gentle approach: mark channel as problematic
    ch.consecutiveErrors++;
    LOGF_W("SSH", "Channel %d: Mutex access issues detected (read=%s, write=%s)", 
           channelIndex, readOk ? "OK" : "STUCK", writeOk ? "OK" : "STUCK");
    
    // If really stuck, close channel gracefully instead of forcing
    if (ch.consecutiveErrors > 10) {
      LOGF_E("SSH", "Channel %d: Too many mutex issues, scheduling graceful close", channelIndex);
      ch.gracefulClosing = true; // Graceful close instead of force
    }
  }
}

// New methods to improve transmission reliability

bool SSHTunnel::processChannelRead(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active || !ch.channel || ch.localSocket < 0) {
    return false;
  }

  // Avant nouvelle lecture, tenter d'enfiler les résidus différés SSH->Local
  if (ch.deferredToLocal && ch.deferredToLocalOffset < ch.deferredToLocalSize) {
    size_t remain = ch.deferredToLocalSize - ch.deferredToLocalOffset;
    size_t q = queueData(channelIndex, ch.deferredToLocal + ch.deferredToLocalOffset, remain, true);
    ch.deferredToLocalOffset += q;
    if (ch.deferredToLocalOffset >= ch.deferredToLocalSize) {
      SAFE_FREE(ch.deferredToLocal); ch.deferredToLocal=nullptr; ch.deferredToLocalSize=ch.deferredToLocalOffset=0;
    }
  }

  if (!lockChannelRead(channelIndex)) {
    return false;
  }

  bool success = false;
  size_t bufferSize = FIXED_BUFFER_SIZE; // Use fixed buffer instead of adaptive
  unsigned long now = millis();

  // OPTIMIZED: Flow control with optimized high/low watermarks for ESP32
  if (ch.flowControlPaused) {
  // Check whether we can resume
    if (ch.queuedBytesToLocal < LOW_WATER_LOCAL) {
      ch.flowControlPaused = false;
  // Only log in DEBUG mode to avoid spam
      #ifdef DEBUG_FLOW_CONTROL
      LOGF_I("SSH", "Channel %d: Flow control RESUME (queuedToLocal=%zu)", 
             channelIndex, ch.queuedBytesToLocal);
      #endif
    } else {
      unlockChannelRead(channelIndex);
  return false; // Stay paused
    }
  }
  
  if (ch.queuedBytesToLocal > HIGH_WATER_LOCAL) {
    ch.flowControlPaused = true;
    LOGF_W("SSH", "Channel %d: Flow control PAUSE (queuedToLocal=%zu)", channelIndex, ch.queuedBytesToLocal);
    unlockChannelRead(channelIndex);
    return false;
  }

  // Double vérification après acquisition du mutex
  if (ch.active && ch.channel && ch.localSocket >= 0) {
  // Check socket state before write
    int sockError = 0;
    socklen_t errLen = sizeof(sockError);
    if (getsockopt(ch.localSocket, SOL_SOCKET, SO_ERROR, &sockError, &errLen) == 0 && sockError != 0) {
      LOGF_I("SSH", "Channel %d: Socket error before write: %s, initiating graceful close", 
             channelIndex, strerror(sockError));
      ch.gracefulClosing = true;
      return false;
    }

    ssize_t bytesRead = libssh2_channel_read(ch.channel, (char *)rxBuffer, bufferSize);
    
    if (bytesRead > 0) {
  // DIAGNOSTIC: Check data consistency for large transfers
      if (ch.largeTransferInProgress && bytesRead > 1024) {
  // Simple check - count non-null bytes to detect corruption
        size_t nonNullBytes = 0;
        for (size_t i = 0; i < bytesRead; i++) {
          if (rxBuffer[i] != 0) nonNullBytes++;
        }
        
  // If more than 90% are zeros, it's suspicious
        if (nonNullBytes < (bytesRead * 0.1)) {
          LOGF_W("SSH", "Channel %d: Suspicious data pattern detected (%zu/%zd non-null)", 
                 channelIndex, nonNullBytes, bytesRead);
        }
      }
      
      // Tenter d'écrire directement vers le socket local
      ssize_t written = send(ch.localSocket, rxBuffer, bytesRead, MSG_DONTWAIT);
      
      if (written == bytesRead) {
  // Full success
        ch.totalBytesReceived += written;
        ch.lastSuccessfulWrite = now;
        if (lockStats()) {
          bytesReceived += written;
          unlockStats();
        }
        success = true;
        
  // DIAGNOSTIC: Log to track large transfers and detect issues
        if (written > 4096) { // > 4KB chunks
          LOGF_I("SSH", "Channel %d: SSH->Local LARGE chunk %zd bytes (total RX: %zu)", 
                 channelIndex, written, ch.totalBytesReceived);
        } else if (ch.largeTransferInProgress) {
          LOGF_D("SSH", "Channel %d: SSH->Local %zd bytes during large transfer (total: %zu)", 
                 channelIndex, written, ch.totalBytesReceived);
        } else {
          LOGF_D("SSH", "Channel %d: SSH->Local %zd bytes (direct)", channelIndex, written);
        }
      } else if (written > 0) {
  // Partial write - queue remaining data
        ch.totalBytesReceived += written;
        ch.lastSuccessfulWrite = now;
        if (lockStats()) {
          bytesReceived += written;
          unlockStats();
        }
        
  // Queue remaining data
        size_t remaining = bytesRead - written;
        size_t q = queueData(channelIndex, rxBuffer + written, remaining, true);
        if (q < remaining) {
          // Stocker résidu non enfilé dans buffer différé
          size_t leftover = remaining - q;
          size_t unqueuedOffset = written + q; // position dans rxBuffer
          if (leftover > 0) {
            // Fusion avec résidu existant si présent
            size_t existing = 0;
            size_t existingRemain = 0;
            if (ch.deferredToLocal) {
              existingRemain = ch.deferredToLocalSize - ch.deferredToLocalOffset;
              existing = existingRemain;
            }
            uint8_t* newBuf = (uint8_t*)safeMalloc(existing + leftover, "DEFER_LOC_RX");
            if (newBuf) {
              size_t pos = 0;
              if (existingRemain > 0) {
                memcpy(newBuf, ch.deferredToLocal + ch.deferredToLocalOffset, existingRemain);
                pos += existingRemain;
              }
              memcpy(newBuf + pos, rxBuffer + unqueuedOffset, leftover);
              SAFE_FREE(ch.deferredToLocal);
              ch.deferredToLocal = newBuf;
              ch.deferredToLocalSize = existingRemain + leftover;
              ch.deferredToLocalOffset = 0; // on repart du début
              LOGF_W("SSH", "Channel %d: Deferred %zu bytes (SSH->Local)", channelIndex, leftover);
            } else {
              LOGF_E("SSH", "Channel %d: Allocation failed for deferred SSH->Local (%zu bytes dropped)", channelIndex, leftover);
              ch.lostWriteChunks++; // comptage diagnostique
              ch.bytesDropped += leftover;
              if (lockStats()) { droppedBytes += leftover; unlockStats(); }
            }
          }
        }
        success = true; // On considère succès (aucune perte des bytes écrits déjà)
      } else if (written < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // Socket full - queue all data
          size_t q = queueData(channelIndex, rxBuffer, bytesRead, true);
          if (q < (size_t)bytesRead) {
            size_t leftover = (size_t)bytesRead - q;
            uint8_t* newBuf = (uint8_t*)safeMalloc(leftover, "DEFER_LOC_RX_FULL");
            if (newBuf) {
              memcpy(newBuf, rxBuffer + q, leftover);
              if (ch.deferredToLocal) { SAFE_FREE(ch.deferredToLocal); }
              ch.deferredToLocal = newBuf;
              ch.deferredToLocalSize = leftover;
              ch.deferredToLocalOffset = 0;
              LOGF_W("SSH", "Channel %d: Deferred %zu bytes (socket full)", channelIndex, leftover);
            } else {
              LOGF_E("SSH", "Channel %d: Allocation failed deferring %zu bytes (drop)", channelIndex, leftover);
              ch.lostWriteChunks++;
              ch.bytesDropped += leftover;
              if (lockStats()) { droppedBytes += leftover; unlockStats(); }
            }
          }
          success = true;
        } else if (errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN || 
                   errno == ESHUTDOWN || errno == ETIMEDOUT) {
          LOGF_I("SSH", "Channel %d: Local connection closed during write (%s), initiating graceful close", 
                 channelIndex, strerror(errno));
          ch.gracefulClosing = true;
          success = true; // Treat as normal close
        } else {
          LOGF_W("SSH", "Channel %d: Local write error: %s (errno=%d)", 
                 channelIndex, strerror(errno), errno);
          ch.consecutiveErrors++;
        }
      }
    } else if (bytesRead == 0) {
      // 0 -> vérifier explicitement EOF
      if (libssh2_channel_eof(ch.channel)) {
        LOGF_I("SSH", "Channel %d: SSH channel EOF", channelIndex);
        ch.gracefulClosing = true;
      }
    } else if (bytesRead < 0 && bytesRead != LIBSSH2_ERROR_EAGAIN) {
      LOGF_W("SSH", "Channel %d: SSH read error: %d", channelIndex, (int)bytesRead);
      ch.consecutiveErrors++;
    }
  }

  unlockChannelRead(channelIndex);
  return success;
}

bool SSHTunnel::processChannelWrite(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active || !ch.channel || ch.localSocket < 0) {
    return false;
  }

  // Backoff: if we recently had an error and are still accumulating, skip this cycle
  unsigned long nowPre = millis();
  if (ch.consecutiveErrors > 0 && (nowPre - ch.lastWriteErrorMs) < 40) {
    return false;
  }

  // Avant nouvelle lecture socket local, tenter de ré-enfiler résidus Local->SSH
  if (ch.deferredToRemote && ch.deferredToRemoteOffset < ch.deferredToRemoteSize) {
    size_t remain = ch.deferredToRemoteSize - ch.deferredToRemoteOffset;
    size_t q = queueData(channelIndex, ch.deferredToRemote + ch.deferredToRemoteOffset, remain, false);
    ch.deferredToRemoteOffset += q;
    if (ch.deferredToRemoteOffset >= ch.deferredToRemoteSize) {
      SAFE_FREE(ch.deferredToRemote); ch.deferredToRemote=nullptr; ch.deferredToRemoteSize=ch.deferredToRemoteOffset=0;
    }
  }

  // Critical backpressure: don't read more if too much is pending
  if (ch.queuedBytesToRemote > CRITICAL_WATER_LOCAL) {
  LOGF_W("SSH", "Channel %d: Critical backpressure (%zu bytes) - skipping local read", 
           channelIndex, ch.queuedBytesToRemote);
    return false;
  }

  if (!lockChannelWrite(channelIndex)) {
    return false;
  }

  bool success = false;
  size_t bufferSize = getOptimalBufferSize(channelIndex);
  unsigned long now = millis();

  if (ch.active && ch.channel && ch.localSocket >= 0) {
  // 1) Loop-drain already queued data (localToSshBuffer)
    size_t totalWritten = 0;
    int passes = 0;
  while (passes < SSH_MAX_WRITES_PER_PASS && ch.localToSshBuffer && !ch.localToSshBuffer->empty()) {
  // Check SSH window
      size_t winSize = 0, winUsed = 0;
  // NOTE: libssh2_channel_window_write_ex signature semble différente sur cible; suppression contrôle fenêtre direct
  // (Future improvement: adapt according to actual header.)
  (void)winSize; (void)winUsed; // silencieux

      uint8_t temp[SSH_BUFFER_SIZE];
      size_t chunk = ch.localToSshBuffer->read(temp, sizeof(temp));
      if (chunk == 0) break;
      if (chunk < MIN_WRITE_SIZE && !ch.localToSshBuffer->empty()) {
  // Try to aggregate a bit more to avoid micro-writes
        size_t extra = ch.localToSshBuffer->read(temp + chunk, MIN_WRITE_SIZE - chunk);
        chunk += extra;
      }

      ssize_t w = libssh2_channel_write_ex(ch.channel, 0, (char*)temp, chunk);
      if (w > 0) {
        passes++;
        totalWritten += w;
        ch.totalBytesSent += w;
        ch.queuedBytesToRemote = (ch.queuedBytesToRemote > (size_t)w) ? ch.queuedBytesToRemote - w : 0;
        ch.lastSuccessfulWrite = now;
        ch.consecutiveErrors = 0;
        if ((size_t)w < chunk) {
          // Put remainder back at head (simple: rewrite) if possible
          ch.localToSshBuffer->write(temp + w, chunk - w);
        }
      } else if (w == LIBSSH2_ERROR_EAGAIN) {
  // Put the whole chunk back
        ch.localToSshBuffer->write(temp, chunk);
        break;
      } else {
        ch.consecutiveErrors++;
        ch.lastWriteErrorMs = now;
        if (w == LIBSSH2_ERROR_SOCKET_RECV) {
          ch.socketRecvErrors++;
        } else if (w == LIBSSH2_ERROR_DECRYPT) {
          ch.fatalCryptoErrors++;
          ch.gracefulClosing = true;
        }
        if (now - ch.lastErrorDetailLogMs > 2000) {
          ch.lastErrorDetailLogMs = now;
          LOGF_W("SSH", "Channel %d: Write error %zd during drain cons=%d sockRecv=%d crypt=%d qRemote=%zu", 
                 channelIndex, w, ch.consecutiveErrors, ch.socketRecvErrors, ch.fatalCryptoErrors, ch.queuedBytesToRemote);
        }
        // Put data back for future retry then exit loop
        ch.localToSshBuffer->write(temp, chunk);
        break;
      }
    }

    if (totalWritten > 0) {
      if (lockStats()) { bytesSent += totalWritten; unlockStats(); }
      LOGF_I("SSH", "Channel %d: Drained %zu bytes in %d passes, %zu queued", 
             channelIndex, totalWritten, passes, ch.queuedBytesToRemote);
      success = true;
    }

  // 2) Read local socket if backpressure acceptable
    if (ch.queuedBytesToRemote < CRITICAL_WATER_LOCAL && isSocketReadable(ch.localSocket, 5)) {
      ssize_t localRead = recv(ch.localSocket, txBuffer, bufferSize, MSG_DONTWAIT);
      if (localRead > 0) {
  // Attempt immediate looped write (direct drainage)
        size_t offset = 0; int directPass = 0; size_t directWrittenTotal = 0;
  while (offset < (size_t)localRead && directPass < SSH_MAX_WRITES_PER_PASS) {
          size_t remain = (size_t)localRead - offset;
          // Check window
            // (SSH window control disabled due to incorrect signature on target)
          ssize_t w = libssh2_channel_write_ex(ch.channel, 0, (char*)txBuffer + offset, remain);
          if (w > 0) {
            offset += w; directPass++; directWrittenTotal += w;
            ch.totalBytesSent += w; ch.lastSuccessfulWrite = now; ch.consecutiveErrors = 0;
            if (lockStats()) { bytesSent += w; unlockStats(); }
          } else if (w == LIBSSH2_ERROR_EAGAIN) {
            break; // Queue the remainder
          } else {
            ch.consecutiveErrors++; 
            ch.lastWriteErrorMs = now;
            if (w == LIBSSH2_ERROR_SOCKET_RECV) ch.socketRecvErrors++;
            else if (w == LIBSSH2_ERROR_DECRYPT) { ch.fatalCryptoErrors++; ch.gracefulClosing = true; }
            if (now - ch.lastErrorDetailLogMs > 2000) {
              ch.lastErrorDetailLogMs = now;
              LOGF_W("SSH","Channel %d: Direct write err %zd cons=%d sockRecv=%d crypt=%d remain=%zu", 
                     channelIndex, w, ch.consecutiveErrors, ch.socketRecvErrors, ch.fatalCryptoErrors, (size_t)localRead - offset);
            }
            break;
          }
        }
        size_t remaining = (size_t)localRead - offset;
        if (remaining > 0) {
          size_t q = queueData(channelIndex, txBuffer + offset, remaining, false);
            if (q < remaining) {
              size_t leftover = remaining - q;
              size_t unqueuedOffset = offset + q;
              size_t existingRemain = 0;
              if (ch.deferredToRemote) {
                existingRemain = ch.deferredToRemoteSize - ch.deferredToRemoteOffset;
              }
              uint8_t* newBuf = (uint8_t*)safeMalloc(existingRemain + leftover, "DEFER_REM_TX");
              if (newBuf) {
                size_t pos = 0;
                if (existingRemain > 0) {
                  memcpy(newBuf, ch.deferredToRemote + ch.deferredToRemoteOffset, existingRemain);
                  pos += existingRemain;
                }
                memcpy(newBuf + pos, txBuffer + unqueuedOffset, leftover);
                SAFE_FREE(ch.deferredToRemote);
                ch.deferredToRemote = newBuf;
                ch.deferredToRemoteSize = existingRemain + leftover;
                ch.deferredToRemoteOffset = 0;
      LOGF_W("SSH", "Channel %d: Deferred %zu bytes (Local->SSH) qRemote=%zu cons=%d", 
        channelIndex, leftover, ch.queuedBytesToRemote, ch.consecutiveErrors);
              } else {
                LOGF_E("SSH", "Channel %d: Allocation failed deferring %zu bytes (drop)", channelIndex, leftover);
                ch.lostWriteChunks++;
                ch.bytesDropped += leftover;
                if (lockStats()) { droppedBytes += leftover; unlockStats(); }
              }
            }
            success = true; // ce qui a été écrit + éventuellement enfilé est conservé
        }
        if (directWrittenTotal>0) {
          LOGF_D("SSH","Channel %d: Direct wrote %zu/%zd bytes (+%zu queued)", channelIndex, directWrittenTotal, localRead, remaining);
        }
      } else if (localRead == 0) {
        LOGF_I("SSH", "Channel %d: Local socket closed", channelIndex);
        ch.gracefulClosing = true;
      } else if (localRead < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOGF_W("SSH", "Channel %d: Local read error %s", channelIndex, strerror(errno));
        ch.consecutiveErrors++;
      }
    }
  }

  unlockChannelWrite(channelIndex);
  return success;
}

void SSHTunnel::processPendingData(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active) {
    return;
  }

  unsigned long now = millis();
  
  // FIX: Increase spacing between calls to reduce contention
  static unsigned long lastProcessTime[10] = {0};
  if (channelIndex < 10 && (now - lastProcessTime[channelIndex]) < 20) { // 20ms au lieu de 10ms
    return;
  }
  lastProcessTime[channelIndex] = now;
  
  // 1) Process SSH->Local buffer (sshToLocalBuffer) - FIXED timeout
  if (xSemaphoreTake(ch.readMutex, pdMS_TO_TICKS(100)) == pdTRUE) { // 100ms instead of 20ms
    if (ch.sshToLocalBuffer && !ch.sshToLocalBuffer->empty() && 
        ch.localSocket >= 0 && isSocketWritable(ch.localSocket, 5)) {
      
      uint8_t tempBuffer[SSH_BUFFER_SIZE];
      size_t bytesRead = ch.sshToLocalBuffer->read(tempBuffer, sizeof(tempBuffer));
      
      if (bytesRead > 0) {
        ssize_t written = send(ch.localSocket, tempBuffer, bytesRead, MSG_DONTWAIT);

        if (written > 0) {
          ch.totalBytesReceived += written;
          ch.queuedBytesToLocal = (ch.queuedBytesToLocal > written) ? ch.queuedBytesToLocal - written : 0;
          ch.consecutiveErrors = 0; // Reset on success
          if (lockStats()) { 
            bytesReceived += written; 
            unlockStats(); 
          }
          
          // If not all sent, put remainder back in buffer
          if (written < bytesRead) {
            ch.sshToLocalBuffer->write(tempBuffer + written, bytesRead - written);
          }
          
          LOGF_D("SSH", "Channel %d: Processed %zd/%zu bytes from SSH->Local buffer", 
                 channelIndex, written, bytesRead);
        } else if (written < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ch.sshToLocalBuffer->write(tempBuffer, bytesRead);
            ch.eagainErrors++;
            if ((ch.eagainErrors % 32) == 1) {
              LOGF_D("SSH", "Channel %d: Socket busy, preserved=%zu (eagain=%d)", channelIndex, bytesRead, ch.eagainErrors);
            }
          } else {
            ch.sshToLocalBuffer->write(tempBuffer, bytesRead);
            ch.consecutiveErrors++;
            LOGF_W("SSH", "Channel %d: Error writing from SSH->Local buffer: %s (err=%d)", channelIndex, strerror(errno), ch.consecutiveErrors);
          }
        } else {
          // written == 0 - socket closed on receive side
          ch.sshToLocalBuffer->write(tempBuffer, bytesRead);
          LOGF_I("SSH", "Channel %d: Local socket closed, %zu bytes preserved", 
                 channelIndex, bytesRead);
        }
      }
    }
    xSemaphoreGive(ch.readMutex);
  } else {
    ch.readMutexFailures++;
    if ((ch.readMutexFailures % 64) == 1) {
      LOGF_D("SSH", "Channel %d: Read mutex busy (failures=%d)", channelIndex, ch.readMutexFailures);
    }
  }
  
  // 2) Process Local->SSH buffer (localToSshBuffer) - FIXED timeout
  if (xSemaphoreTake(ch.writeMutex, pdMS_TO_TICKS(100)) == pdTRUE) { // 100ms instead of 20ms
    if (ch.localToSshBuffer && !ch.localToSshBuffer->empty() && ch.channel) {
      const int maxWritesThisPass = 6; // Conservative per-loop drain cap (overrides global macro 8)
      int passes = 0;
      size_t totalWrittenThisPass = 0;
      while (passes < maxWritesThisPass && !ch.localToSshBuffer->empty()) {
        uint8_t tempBuffer[SSH_BUFFER_SIZE];
        size_t bytesRead = ch.localToSshBuffer->read(tempBuffer, sizeof(tempBuffer));
        if (bytesRead == 0) break;
        ssize_t written = libssh2_channel_write(ch.channel, (char*)tempBuffer, bytesRead);
        if (written > 0) {
          passes++;
          totalWrittenThisPass += written;
          ch.totalBytesSent += written;
          ch.queuedBytesToRemote = (ch.queuedBytesToRemote > written) ? ch.queuedBytesToRemote - written : 0;
          ch.consecutiveErrors = 0;
          if (lockStats()) { bytesSent += written; unlockStats(); }
          if ((size_t)written < bytesRead) {
            ch.localToSshBuffer->write(tempBuffer + written, bytesRead - written);
            break; // Reduced SSH window: stop draining
          }
        } else if (written == LIBSSH2_ERROR_EAGAIN) {
          // Remettre intégralement le chunk
          ch.localToSshBuffer->write(tempBuffer, bytesRead);
          ch.eagainErrors++;
            if ((ch.eagainErrors % 32) == 1) {
              LOGF_D("SSH", "Channel %d: SSH channel busy mid-drain (eagain=%d passes=%d total=%zu)", channelIndex, ch.eagainErrors, passes, totalWrittenThisPass);
            }
          break; // SSH window full
        } else if (written == 0) {
          // Canal fermé
          ch.localToSshBuffer->write(tempBuffer, bytesRead);
          LOGF_I("SSH", "Channel %d: SSH channel closed, %zu bytes preserved", channelIndex, bytesRead);
          break;
        } else { // Erreur négative
          ch.localToSshBuffer->write(tempBuffer, bytesRead);
          ch.consecutiveErrors++;
          LOGF_W("SSH", "Channel %d: Write error %zd (err=%d)", channelIndex, written, ch.consecutiveErrors);
          break;
        }
      }
      if (totalWrittenThisPass > 0) {
        LOGF_D("SSH", "Channel %d: Drained %zu bytes in %d passes (queuedRemote=%zu)", channelIndex, totalWrittenThisPass, passes, ch.queuedBytesToRemote);
      }
    }
    xSemaphoreGive(ch.writeMutex);
  } else {
    ch.writeMutexFailures++;
    if ((ch.writeMutexFailures % 64) == 1) {
      LOGF_D("SSH", "Channel %d: Write mutex busy (failures=%d)", channelIndex, ch.writeMutexFailures);
    }
  }

  // 3) Resume flow control if we've dropped below the LOW watermark
  if (ch.flowControlPaused && ch.queuedBytesToLocal < LOW_WATER_LOCAL) {
    ch.flowControlPaused = false;
    LOGF_D("SSH", "Channel %d: Flow control resumed (below %d bytes)", channelIndex, LOW_WATER_LOCAL);
  }
}

bool SSHTunnel::queueData(int channelIndex, uint8_t* data, size_t size, bool isRead) {
  size_t q = queueData(channelIndex, (const uint8_t*)data, size, isRead);
  return q == size;
}

// NEW: queueData version retournant le nombre d'octets effectivement enfilés
size_t SSHTunnel::queueData(int channelIndex, const uint8_t* data, size_t size, bool isRead) {
  if (channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) return 0;
  if (!data || size == 0) return 0;
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active) return 0;
  DataRingBuffer* targetBuffer = isRead ? ch.sshToLocalBuffer : ch.localToSshBuffer;
  SemaphoreHandle_t mutex = isRead ? ch.readMutex : ch.writeMutex;
  bool locked = false;
  if (mutex) locked = (xSemaphoreTake(mutex, 0) == pdTRUE);
  size_t remaining = size;
  const uint8_t* cursor = data;
  size_t totalQueued = 0;
  while (remaining > 0) {
    size_t chunk = remaining > SSH_BUFFER_SIZE ? SSH_BUFFER_SIZE : remaining;
    size_t w = targetBuffer->write(cursor, chunk);
    if (w == 0) break;
    totalQueued += w;
    remaining -= w;
    cursor += w;
    if (isRead) ch.queuedBytesToLocal += w; else ch.queuedBytesToRemote += w;
  }
  ch.lastActivity = millis();
  if (locked) xSemaphoreGive(mutex);
  if (totalQueued == 0) {
    ch.lostWriteChunks++;
    if (ch.lostWriteChunks % 10 == 1) {
      LOGF_W("SSH", "Channel %d: Buffer full - 0 bytes enqueued (lostChunks=%d)", channelIndex, ch.lostWriteChunks);
    }
  }
  return totalQueued;
}

void SSHTunnel::flushPendingData(int channelIndex) {
  if (channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) return;
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active) return;

  // 1. Tenter de drainer les buffers différés vers les rings
  if (ch.deferredToLocal && ch.deferredToLocalOffset < ch.deferredToLocalSize) {
    size_t remain = ch.deferredToLocalSize - ch.deferredToLocalOffset;
    size_t q = queueData(channelIndex, ch.deferredToLocal + ch.deferredToLocalOffset, remain, true);
    ch.deferredToLocalOffset += q;
    if (ch.deferredToLocalOffset >= ch.deferredToLocalSize) { SAFE_FREE(ch.deferredToLocal); ch.deferredToLocal=nullptr; ch.deferredToLocalSize=ch.deferredToLocalOffset=0; }
  }
  if (ch.deferredToRemote && ch.deferredToRemoteOffset < ch.deferredToRemoteSize) {
    size_t remain = ch.deferredToRemoteSize - ch.deferredToRemoteOffset;
    size_t q = queueData(channelIndex, ch.deferredToRemote + ch.deferredToRemoteOffset, remain, false);
    ch.deferredToRemoteOffset += q;
    if (ch.deferredToRemoteOffset >= ch.deferredToRemoteSize) { SAFE_FREE(ch.deferredToRemote); ch.deferredToRemote=nullptr; ch.deferredToRemoteSize=ch.deferredToRemoteOffset=0; }
  }

  // 2. SSH->Local ring vers socket
  if (ch.sshToLocalBuffer && !ch.sshToLocalBuffer->empty() && ch.localSocket >= 0) {
    if (lockChannelRead(channelIndex)) {
      uint8_t temp[SSH_BUFFER_SIZE];
      size_t peeked = ch.sshToLocalBuffer->peek(temp, sizeof(temp));
      if (peeked > 0) {
        ssize_t w = send(ch.localSocket, temp, peeked, MSG_DONTWAIT);
        if (w > 0) {
          uint8_t dump[SSH_BUFFER_SIZE];
          ch.sshToLocalBuffer->read(dump, (size_t)w);
          ch.queuedBytesToLocal = (ch.queuedBytesToLocal > (size_t)w) ? ch.queuedBytesToLocal - (size_t)w : 0;
          if ((size_t)w < peeked) {
            // remainder reste dans le ring, rien à faire
          }
        } else if (w < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK)) {
          LOGF_W("SSH", "Channel %d: flushPendingData local send err %s", channelIndex, strerror(errno));
        }
      }
      unlockChannelRead(channelIndex);
    }
  }

  // 3. Local->SSH ring vers SSH
  if (ch.localToSshBuffer && !ch.localToSshBuffer->empty() && ch.channel) {
    if (lockChannelWrite(channelIndex)) {
      uint8_t temp[SSH_BUFFER_SIZE];
      size_t peeked = ch.localToSshBuffer->peek(temp, sizeof(temp));
      if (peeked > 0) {
        ssize_t w = libssh2_channel_write_ex(ch.channel, 0, (char*)temp, peeked);
        if (w > 0) {
          uint8_t dump[SSH_BUFFER_SIZE];
            ch.localToSshBuffer->read(dump, (size_t)w);
            ch.queuedBytesToRemote = (ch.queuedBytesToRemote > (size_t)w) ? ch.queuedBytesToRemote - (size_t)w : 0;
          ch.lastSuccessfulWrite = millis();
          ch.consecutiveErrors = 0;
        } else if (w == LIBSSH2_ERROR_EAGAIN) {
          // benign, try later
        } else if (w < 0) {
          unsigned long nowMs = millis();
          ch.consecutiveErrors++;
          ch.lastWriteErrorMs = nowMs;
          if (w == LIBSSH2_ERROR_SOCKET_RECV) {
            ch.socketRecvErrors++;
          } else if (w == LIBSSH2_ERROR_DECRYPT) {
            ch.fatalCryptoErrors++;
            ch.gracefulClosing = true; // Force channel to wind down
          }
          // Throttled detailed log (every 2000ms if still erroring)
          if (nowMs - ch.lastErrorDetailLogMs > 2000) {
            ch.lastErrorDetailLogMs = nowMs;
            LOGF_W("SSH", "Channel %d: flushPendingData SSH write err %zd cons=%d sockRecv=%d crypt=%d qRemote=%zu defRem=%zu", 
                   channelIndex, w, ch.consecutiveErrors, ch.socketRecvErrors, ch.fatalCryptoErrors,
                   ch.queuedBytesToRemote,
                   (size_t)(ch.deferredToRemote ? (ch.deferredToRemoteSize - ch.deferredToRemoteOffset) : 0));
          }
        }
      }
      unlockChannelWrite(channelIndex);
    }
  }
}

bool SSHTunnel::isChannelHealthy(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active) {
    return false;
  }
  
  unsigned long now = millis();
  
  // Fatal crypto error -> immediately unhealthy
  if (ch.fatalCryptoErrors > 0) {
    LOGF_D("SSH", "Channel %d: Unhealthy (fatal crypto errors=%d)", channelIndex, ch.fatalCryptoErrors);
    return false;
  }
  // Socket recv errors escalation
  if (ch.socketRecvErrors > 4) {
    LOGF_D("SSH", "Channel %d: Unhealthy (socketRecvErrors=%d)", channelIndex, ch.socketRecvErrors);
    return false;
  }
  // Vérifier les erreurs consécutives
  if (ch.consecutiveErrors > 3) {
    LOGF_D("SSH", "Channel %d: Unhealthy due to %d consecutive errors", channelIndex, ch.consecutiveErrors);
    return false;
  }
  
  // Vérifier la dernière activité (réduit de 5 minutes à 2 minutes)
  if (now - ch.lastActivity > 120000) { // 2 minutes
    LOGF_D("SSH", "Channel %d: Unhealthy due to inactivity (%lums)", channelIndex, now - ch.lastActivity);
    return false;
  }
  

  // Vérifier si les buffers unifiés ne sont pas trop pleins (réduit les seuils)
  if (ch.sshToLocalBuffer && ch.sshToLocalBuffer->size() > 20 * 1024) { // 20KB max
    LOGF_D("SSH", "Channel %d: Unhealthy due to SSH->Local buffer size (%zu)", channelIndex, ch.sshToLocalBuffer->size());
    return false;
  }
  if (ch.localToSshBuffer && ch.localToSshBuffer->size() > 20 * 1024) { // 20KB max
    LOGF_D("SSH", "Channel %d: Unhealthy due to Local->SSH buffer size (%zu)", channelIndex, ch.localToSshBuffer->size());
    return false;
  }
  

  if (ch.queuedBytesToLocal + ch.queuedBytesToRemote > MAX_QUEUED_BYTES) {
    LOGF_D("SSH", "Channel %d: Unhealthy due to excessive queued bytes (%zu total)", 
           channelIndex, ch.queuedBytesToLocal + ch.queuedBytesToRemote);
    return false;
  }
  
  // NOUVEAU: Vérifier l'état des mutex
  if (ch.readMutex) {
    if (xSemaphoreTake(ch.readMutex, 0) == pdTRUE) {
      xSemaphoreGive(ch.readMutex);
    } else {
      LOGF_D("SSH", "Channel %d: Unhealthy due to blocked read mutex", channelIndex);
      return false;
    }
  }
  
  if (ch.writeMutex) {
    if (xSemaphoreTake(ch.writeMutex, 0) == pdTRUE) {
      xSemaphoreGive(ch.writeMutex);
    } else {
      LOGF_D("SSH", "Channel %d: Unhealthy due to blocked write mutex", channelIndex);
      return false;
    }
  }
  
  return true;
}

void SSHTunnel::recoverChannel(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  
  // OPTIMISÉ: Essayer d'abord une récupération gracieuse
  if (ch.consecutiveErrors < 5) {
    LOGF_I("SSH", "Channel %d: Attempting graceful recovery (errors: %d)", channelIndex, ch.consecutiveErrors);
    gracefulRecoverChannel(channelIndex);
    return;
  }
  
  // Si la récupération gracieuse a échoué trop de fois, récupération forcée
  LOGF_W("SSH", "Channel %d: Too many errors (%d), forcing hard recovery", channelIndex, ch.consecutiveErrors);
  
  // NOUVEAU: Force la libération des mutex bloqués
  if (ch.readMutex) {
    // Vérifier si le mutex est bloqué en essayant de l'acquérir rapidement
    if (xSemaphoreTake(ch.readMutex, 0) == pdTRUE) {
      xSemaphoreGive(ch.readMutex); // Il était libre, on le rend
    } else {
      // Le mutex semble bloqué, forcer la création d'un nouveau
      LOGF_W("SSH", "Channel %d: Read mutex appears stuck, recreating", channelIndex);
      vSemaphoreDelete(ch.readMutex);
      ch.readMutex = xSemaphoreCreateMutex();
      if (!ch.readMutex) {
        LOGF_E("SSH", "Channel %d: Failed to recreate read mutex", channelIndex);
      }
    }
  }
  
  if (ch.writeMutex) {
    if (xSemaphoreTake(ch.writeMutex, 0) == pdTRUE) {
      xSemaphoreGive(ch.writeMutex); // Il était libre, on le rend
    } else {
      // Le mutex semble bloqué, forcer la création d'un nouveau
      LOGF_W("SSH", "Channel %d: Write mutex appears stuck, recreating", channelIndex);
      vSemaphoreDelete(ch.writeMutex);
      ch.writeMutex = xSemaphoreCreateMutex();
      if (!ch.writeMutex) {
        LOGF_E("SSH", "Channel %d: Failed to recreate write mutex", channelIndex);
      }
    }
  }
  
  // OPTIMISÉ: Seulement maintenant vider les données en cas de récupération forcée
  flushPendingData(channelIndex);
  
  // Reset des compteurs d'erreurs
  ch.consecutiveErrors = 0;
  ch.eagainErrors = 0;
  ch.flowControlPaused = false;
  ch.pendingBytes = 0;
  
  // Vérifier l'état des sockets/canaux
  if (ch.localSocket >= 0) {
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(ch.localSocket, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
      LOGF_W("SSH", "Channel %d: Local socket error during recovery, closing", channelIndex);
      closeChannel(channelIndex);
      return;
    }
  }
  
  if (ch.channel && libssh2_channel_eof(ch.channel)) {
    LOGF_W("SSH", "Channel %d: SSH channel EOF during recovery, closing", channelIndex);
    closeChannel(channelIndex);
    return;
  }
  
  ch.lastActivity = millis();
  LOGF_I("SSH", "Channel %d: Hard recovery completed", channelIndex);
}

size_t SSHTunnel::getOptimalBufferSize(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  const size_t MIN_BUFFER_SIZE = 1024; // Jamais en dessous
  const size_t MAX_BUFFER_SIZE = 1460; // MTU typique Ethernet
  size_t baseSize = config->getConnectionConfig().bufferSize;
  if (baseSize < MIN_BUFFER_SIZE) baseSize = MIN_BUFFER_SIZE;

  // Si erreurs persistantes, rester à la taille minimale sûre
  if (ch.consecutiveErrors > 5) {
    return MIN_BUFFER_SIZE;
  }

  // Pour gros transfert stable on peut légèrement augmenter (max MTU)
  if (ch.largeTransferInProgress && ch.consecutiveErrors == 0) {
    size_t boosted = (size_t)(baseSize * 1.2f);
    if (boosted > MAX_BUFFER_SIZE) boosted = MAX_BUFFER_SIZE;
    return boosted;
  }
  return baseSize;
}

bool SSHTunnel::isSocketReadable(int sockfd, int timeoutMs) {
  if (sockfd < 0) return false;
  
  // Vérifier d'abord l'état du socket avec getsockopt
  int sockError = 0;
  socklen_t errLen = sizeof(sockError);
  if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sockError, &errLen) == 0 && sockError != 0) {
    LOGF_D("SSH", "Socket %d error in isSocketReadable: %s", sockfd, strerror(sockError));
    return false;
  }

  fd_set rfds, errfds;
  FD_ZERO(&rfds);
  FD_ZERO(&errfds);
  FD_SET(sockfd, &rfds);
  FD_SET(sockfd, &errfds); // Surveiller aussi les erreurs
  
  struct timeval tv;
  tv.tv_sec  = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  
  int r = lwip_select(sockfd + 1, &rfds, nullptr, &errfds, (timeoutMs >= 0 ? &tv : nullptr));
  if (r <= 0) return false;
  
  // Vérifier s'il y a une erreur sur le socket
  if (FD_ISSET(sockfd, &errfds)) {
    LOGF_D("SSH", "Socket %d error detected in select", sockfd);
    return false;
  }
  
  return FD_ISSET(sockfd, &rfds);
}

bool SSHTunnel::isSocketWritable(int sockfd, int timeoutMs) {
  if (sockfd < 0) return false;
  
  // Vérifier d'abord l'état du socket
  int sockError = 0;
  socklen_t errLen = sizeof(sockError);
  if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sockError, &errLen) == 0 && sockError != 0) {
    LOGF_D("SSH", "Socket %d error in isSocketWritable: %s", sockfd, strerror(sockError));
    return false;
  }

  fd_set wfds, errfds;
  FD_ZERO(&wfds);
  FD_ZERO(&errfds);
  FD_SET(sockfd, &wfds);
  FD_SET(sockfd, &errfds);
  
  struct timeval tv;
  tv.tv_sec  = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  
  int r = lwip_select(sockfd + 1, nullptr, &wfds, &errfds, (timeoutMs >= 0 ? &tv : nullptr));
  if (r <= 0) return false;
  
  if (FD_ISSET(sockfd, &errfds)) {
    LOGF_D("SSH", "Socket %d error detected in writable select", sockfd);
    return false;
  }
  
  return FD_ISSET(sockfd, &wfds);
}

// NOUVEAU: Méthode pour détecter et récupérer les deadlocks
void SSHTunnel::checkAndRecoverDeadlocks() {
  if (!channels) return;
  
  unsigned long now = millis();
  int maxChannels = config->getConnectionConfig().maxChannels;
  static unsigned long lastChannelActivity[10] = {0}; // Suivi de l'activité par canal (max 10 canaux)
  
  for (int i = 0; i < maxChannels && i < 10; i++) {
    TunnelChannel &ch = channels[i];
    if (!ch.active) continue;
    
    // Vérifier si le canal est "collé" (pas d'activité depuis 30 secondes)
    bool channelStuck = (now - ch.lastActivity) > 30000;
    
    // Vérifier les mutex bloqués en tentant une acquisition rapide
    bool readMutexStuck = false, writeMutexStuck = false;
    
    if (ch.readMutex) {
      if (xSemaphoreTake(ch.readMutex, 0) == pdTRUE) {
        xSemaphoreGive(ch.readMutex); // Était libre
      } else {
        readMutexStuck = true;
      }
    }
    
    if (ch.writeMutex) {
      if (xSemaphoreTake(ch.writeMutex, 0) == pdTRUE) {
        xSemaphoreGive(ch.writeMutex); // Était libre
      } else {
        writeMutexStuck = true;
      }
    }
    
    // Détecter un deadlock probable
    bool deadlockDetected = channelStuck && (readMutexStuck || writeMutexStuck);
    
    // Vérifier si les buffers unifiés sont anormalement pleins
    bool buffersOverloaded = false;
    if (ch.sshToLocalBuffer && ch.sshToLocalBuffer->size() > 45 * 1024) buffersOverloaded = true; // Plus de 45KB en attente
    if (ch.localToSshBuffer && ch.localToSshBuffer->size() > 45 * 1024) buffersOverloaded = true;
    
    if (deadlockDetected || buffersOverloaded) {
      LOGF_W("SSH", "Channel %d: Deadlock detected (stuck=%s, rMutex=%s, wMutex=%s, bufOverload=%s) - triggering recovery", 
             i, channelStuck ? "YES" : "NO", 
             readMutexStuck ? "STUCK" : "OK",
             writeMutexStuck ? "STUCK" : "OK",
             buffersOverloaded ? "YES" : "NO");
      
      recoverChannel(i);
      lastChannelActivity[i] = now; // Reset le timer
    } else {
      // Mettre à jour le timer d'activité normale
      if (ch.lastActivity > lastChannelActivity[i]) {
        lastChannelActivity[i] = ch.lastActivity;
      }
    }
  }
}

// NOUVEAU: Diagnostic détaillé des transferts de données
void SSHTunnel::printDataTransferStats(int channelIndex) {
  if (!channels || channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }
  
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active) return;
  
  size_t sshToLocalSize = ch.sshToLocalBuffer ? ch.sshToLocalBuffer->size() : 0;
  size_t localToSshSize = ch.localToSshBuffer ? ch.localToSshBuffer->size() : 0;
  
  LOGF_I("SSH", "Channel %d Transfer Stats:", channelIndex);
  LOGF_I("SSH", "  - Total RX: %zu bytes, TX: %zu bytes", ch.totalBytesReceived, ch.totalBytesSent);
  LOGF_I("SSH", "  - Queued to Local: %zu, to Remote: %zu", ch.queuedBytesToLocal, ch.queuedBytesToRemote);
  LOGF_I("SSH", "  - Buffers: SSH->Local=%zu bytes, Local->SSH=%zu bytes", sshToLocalSize, localToSshSize);
  LOGF_I("SSH", "  - Lost chunks: %d, Dropped bytes: %zu, Consecutive errors: %d, EAGAIN errors: %d", ch.lostWriteChunks, ch.bytesDropped, ch.consecutiveErrors, ch.eagainErrors);
  
  // Calculer le ratio de buffer utilization
  size_t totalQueued = ch.queuedBytesToLocal + ch.queuedBytesToRemote;
  size_t totalBuffered = sshToLocalSize + localToSshSize;
  size_t totalTransferred = ch.totalBytesReceived + ch.totalBytesSent;
  
  if (totalTransferred > 0) {
    float bufferRatio = (float)(totalQueued + totalBuffered) / totalTransferred * 100.0f;
    LOGF_I("SSH", "  - Buffer/Transfer ratio: %.1f%% %s", bufferRatio,
           bufferRatio > 50.0f ? "(WARNING: High buffer usage!)" : "");
  }
}

// ====== NOUVELLES MÉTHODES POUR LA GESTION DES GROS TRANSFERTS ======

bool SSHTunnel::isLargeTransferActive() {
  int maxChannels = config->getConnectionConfig().maxChannels;
  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active && channels[i].largeTransferInProgress) {
      return true;
    }
  }
  return false;
}

void SSHTunnel::detectLargeTransfer(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active) return;
  
  unsigned long now = millis();
  unsigned long transferDuration = now - ch.transferStartTime;
  
  // CORRECTION: Calculer le débit de manière plus conservative
  if (transferDuration > 2000) { // Au moins 2 secondes de données pour éviter les faux positifs
    size_t totalTransferred = ch.totalBytesReceived + ch.totalBytesSent;
    size_t currentRate = totalTransferred * 1000 / transferDuration;
    
    if (currentRate > ch.peakBytesPerSecond) {
      ch.peakBytesPerSecond = currentRate;
    }
    
    // CORRECTION: Critères plus stricts pour éviter les faux positifs
    bool wasLargeTransfer = ch.largeTransferInProgress;
    
    ch.largeTransferInProgress = (
      totalTransferred > LARGE_TRANSFER_THRESHOLD &&
      currentRate > LARGE_TRANSFER_RATE_THRESHOLD &&
      transferDuration > LARGE_TRANSFER_TIME_THRESHOLD &&
      ((ch.sshToLocalBuffer && ch.sshToLocalBuffer->size() > 10 * 1024) || 
       (ch.localToSshBuffer && ch.localToSshBuffer->size() > 10 * 1024)) // Buffer activity (>10KB)
    );
    
    // Log uniquement lors des changements d'état
    if (ch.largeTransferInProgress && !wasLargeTransfer) {
      LOGF_I("SSH", "Channel %d: Large transfer detected - Rate: %zu B/s, Total: %zu bytes", 
             channelIndex, currentRate, totalTransferred);
    } else if (!ch.largeTransferInProgress && wasLargeTransfer) {
      LOGF_I("SSH", "Channel %d: Large transfer completed - Peak: %zu B/s, Total: %zu bytes", 
             channelIndex, ch.peakBytesPerSecond, totalTransferred);
    }
  }
}

bool SSHTunnel::shouldAcceptNewConnection() {
  int activeChannels = getActiveChannels();
  int maxChannels = config->getConnectionConfig().maxChannels;
  if (activeChannels >= maxChannels) return false;

  // Refuser si gros transfert actif sur un canal
  if (isLargeTransferActive()) {
    return false;
  }

  // Refuser si un canal existant est surchargé ou instable
  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active) {
      if (channels[i].queuedBytesToRemote > (HIGH_WATER_LOCAL + 512)) {
        LOGF_D("SSH", "Reject new conn: channel %d backlog %zu", i, channels[i].queuedBytesToRemote);
        return false;
      }
      if (channels[i].consecutiveErrors > 2) {
        LOGF_D("SSH", "Reject new conn: channel %d errors %d", i, channels[i].consecutiveErrors);
        return false;
      }
    }
  }

  // Limiter utilisation à 70% avant refus proactif
  if (activeChannels >= (int)(0.7f * maxChannels)) {
    // Autoriser quand même si aucun backlog sévère
    return true;
  }
  return true;
}

void SSHTunnel::queuePendingConnection(LIBSSH2_CHANNEL* channel) {
  if (!channel) return;
  
  // Protéger l'accès à la file d'attente
  if (xSemaphoreTake(pendingConnectionsMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    // Limiter la taille de la file d'attente
    const size_t MAX_PENDING = 5;
    
    if (pendingConnections.size() >= MAX_PENDING) {
      // Fermer la plus ancienne connexion en attente
      PendingConnection& oldest = pendingConnections.front();
      LOGF_W("SSH", "Pending connections queue full - closing oldest connection");
      
      libssh2_channel_close(oldest.channel);
      libssh2_channel_free(oldest.channel);
      pendingConnections.erase(pendingConnections.begin());
    }
    
    // Ajouter la nouvelle connexion
    PendingConnection pending;
    pending.channel = channel;
    pending.timestamp = millis();
    pendingConnections.push_back(pending);
    
    LOGF_I("SSH", "Connection queued - %zu connections waiting", pendingConnections.size());
    
    xSemaphoreGive(pendingConnectionsMutex);
  } else {
    // Impossible d'acquérir le mutex - fermer la connexion
    LOGF_E("SSH", "Could not acquire mutex for pending connections - closing connection");
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);
  }
}

bool SSHTunnel::processPendingConnections() {
  if (pendingConnections.empty()) return false;
  
  if (xSemaphoreTake(pendingConnectionsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
    unsigned long now = millis();
    const unsigned long MAX_WAIT_TIME = 30000; // 30 secondes max d'attente
    
    for (auto it = pendingConnections.begin(); it != pendingConnections.end();) {
      // Vérifier si la connexion a expiré
      if (now - it->timestamp > MAX_WAIT_TIME) {
        LOGF_W("SSH", "Pending connection expired - closing");
        libssh2_channel_close(it->channel);
        libssh2_channel_free(it->channel);
        it = pendingConnections.erase(it);
        continue;
      }
      
      // Essayer de traiter cette connexion
      if (shouldAcceptNewConnection()) {
        LIBSSH2_CHANNEL* channel = it->channel;
        LOGF_I("SSH", "Processing pending connection - %zu remaining", pendingConnections.size() - 1);
        
        // Supprimer de la file avant traitement
        it = pendingConnections.erase(it);
        
        // Libérer le mutex temporairement pour traiter la connexion
        xSemaphoreGive(pendingConnectionsMutex);
        
        // Traiter la connexion (copie du code de handleNewConnection)
        if (!processQueuedConnection(channel)) {
          // Si échec, fermer la connexion
          libssh2_channel_close(channel);
          libssh2_channel_free(channel);
        }
        
        return true; // Une connexion traitée
      } else {
        ++it; // Passer à la suivante
      }
    }
    
    xSemaphoreGive(pendingConnectionsMutex);
  }
  
  return false;
}

bool SSHTunnel::processQueuedConnection(LIBSSH2_CHANNEL* channel) {
  // Cette méthode est identique à la partie de handleNewConnection qui traite une connexion
  // Find available channel slot avec réutilisation agressive
  int channelIndex = -1;
  int maxChannels = config->getConnectionConfig().maxChannels;
  unsigned long now = millis();
  
  // Première passe : chercher un canal vraiment libre
  for (int i = 0; i < maxChannels; i++) {
    LOGF_D("SSH", "Trying to open new channel slot %d (active=%d)", i, channels[i].active);
    if (!channels[i].active) {
      channelIndex = i;
      LOGF_I("SSH", "Found available channel slot %d", i);
      break;
    }
  }

  // Si aucun canal libre, chercher des canaux "nettoyables" (inactifs depuis longtemps)
  if (channelIndex == -1) {
    for (int i = 0; i < maxChannels; i++) {
      if (channels[i].active && (now - channels[i].lastActivity) > 30000) { // 30 secondes
        LOGF_I("SSH", "Reusing inactive channel slot %d (inactive for %lums)", 
               i, now - channels[i].lastActivity);
        closeChannel(i); // Force la fermeture
        channelIndex = i;
        break;
      }
    }
  }

  if (channelIndex == -1) {
    LOGF_W("SSH", "No available channel slots (active: %d/%d), closing queued connection", 
           getActiveChannels(), maxChannels);
    return false;
  }

  // Create socket and connect to local endpoint
  int localSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (localSocket < 0) {
    LOG_E("SSH", "Failed to create local socket");
    return false;
  }

  // Utiliser la configuration pour l'endpoint local
  const TunnelConfig& tunnelConfig = config->getTunnelConfig();
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(tunnelConfig.localPort);
  inet_pton(AF_INET, tunnelConfig.localHost.c_str(), &addr.sin_addr);

  if (::connect(localSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOGF_E("SSH", "Failed to connect to local endpoint %s:%d", 
           tunnelConfig.localHost.c_str(), tunnelConfig.localPort);
    close(localSocket);
    return false;
  }

  // Optimiser le socket local pour les performances
  if (!NetworkOptimizer::optimizeSocket(localSocket)) {
    LOGF_W("SSH", "Warning: Could not optimize local socket for channel %d", channelIndex);
  }

  // Set socket non-blocking
  int flags = fcntl(localSocket, F_GETFL, 0);
  fcntl(localSocket, F_SETFL, flags | O_NONBLOCK);

  // Set up channel
  channels[channelIndex].channel = channel;
  channels[channelIndex].localSocket = localSocket;
  channels[channelIndex].active = true;
  channels[channelIndex].lastActivity = millis();
  channels[channelIndex].pendingBytes = 0;
  channels[channelIndex].flowControlPaused = false;
  // Reset per-channel reliability counters
  channels[channelIndex].consecutiveErrors = 0;
  channels[channelIndex].eagainErrors = 0;
  channels[channelIndex].readMutexFailures = 0;
  channels[channelIndex].writeMutexFailures = 0;
  channels[channelIndex].lostWriteChunks = 0;
  channels[channelIndex].queuedBytesToLocal = 0;
  channels[channelIndex].queuedBytesToRemote = 0;
  
  // Initialiser les variables de détection des gros transferts
  channels[channelIndex].largeTransferInProgress = false;
  channels[channelIndex].transferStartTime = millis();
  channels[channelIndex].transferredBytes = 0;
  channels[channelIndex].peakBytesPerSecond = 0;

  libssh2_channel_set_blocking(channel, 0);

  LOGF_I("SSH", "Queued tunnel connection established (channel %d)", channelIndex);
  return true;
}

// ====== NOUVELLES MÉTHODES OPTIMISÉES ======

// NOUVEAU: Tâche dédiée pour le traitement des données (pattern producer/consumer)
void SSHTunnel::dataProcessingTaskWrapper(void* parameter) {
  SSHTunnel* tunnel = static_cast<SSHTunnel*>(parameter);
  tunnel->dataProcessingTaskFunction();
}

void SSHTunnel::dataProcessingTaskFunction() {
  while (dataProcessingTaskRunning) {
    // Wait for work signal or longer timeout to reduce contention
    if (xSemaphoreTake(dataProcessingSemaphore, pdMS_TO_TICKS(200)) == pdTRUE) { // 200ms instead of 100ms
      if (!dataProcessingTaskRunning) break;
      
      int maxChannels = config->getConnectionConfig().maxChannels;
      static unsigned long lastMutexProbe = 0;
  bool doProbe = (millis() - lastMutexProbe) > 3000; // every 3s
      if (doProbe) lastMutexProbe = millis();
      for (int i = 0; i < maxChannels; i++) {
        if (channels[i].active) {
          // Check if there's really work before processing
          bool hasWork = false;
          if (channels[i].sshToLocalBuffer && !channels[i].sshToLocalBuffer->empty()) hasWork = true;
          if (channels[i].localToSshBuffer && !channels[i].localToSshBuffer->empty()) hasWork = true;
          
          if (hasWork) {
            processPendingData(i);
          }
          
          // Graceful handling of closing channels
          if (channels[i].gracefulClosing) {
            processPendingData(i);
          }

          // Sondage doux périodique des mutex si activité réduite
          if (doProbe && !channels[i].gracefulClosing) {
            safeRetryMutexAccess(i);
          }
          
          // Check large transfers less frequently
          static unsigned long lastLargeTransferCheck = 0;
          if (millis() - lastLargeTransferCheck > 5000) { // Every 5s instead of each loop
            detectLargeTransfer(i);
            lastLargeTransferCheck = millis();
          }
        }
      }
    }
    
    // Longer pause to reduce CPU usage
    vTaskDelay(pdMS_TO_TICKS(10)); // 10ms instead of 5ms
  }
  
  // Nettoyer avant de terminer
  dataProcessingTask = nullptr;
  vTaskDelete(NULL);
}

bool SSHTunnel::startDataProcessingTask() {
  if (dataProcessingTask != nullptr) {
    return true; // Déjà démarrée
  }
  
  dataProcessingTaskRunning = true;
  
  BaseType_t result = xTaskCreate(
    dataProcessingTaskWrapper,
    "SSH_DataProcessing",
    4096, // Stack size
    this,
    tskIDLE_PRIORITY + 1, // FIXED: Reduced priority to avoid contention
    &dataProcessingTask
  );
  
  if (result != pdPASS) {
    LOG_E("SSH", "Failed to create data processing task");
    dataProcessingTaskRunning = false;
    return false;
  }
  
  LOG_I("SSH", "Data processing task started successfully with reduced priority");
  return true;
}

void SSHTunnel::stopDataProcessingTask() {
  if (dataProcessingTask == nullptr) {
    return; // Pas démarrée
  }
  
  dataProcessingTaskRunning = false;
  
  // Signaler la tâche pour qu'elle se termine
  if (dataProcessingSemaphore) {
    xSemaphoreGive(dataProcessingSemaphore);
  }
  
  // Attendre que la tâche se termine (timeout 1 seconde)
  unsigned long startTime = millis();
  while (dataProcessingTask != nullptr && (millis() - startTime) < 1000) {
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  
  if (dataProcessingTask != nullptr) {
    LOG_W("SSH", "Force terminating data processing task");
    vTaskDelete(dataProcessingTask);
    dataProcessingTask = nullptr;
  }
  
  LOG_I("SSH", "Data processing task stopped");
}

// NOUVEAU: Récupération gracieuse sans effacer les buffers
void SSHTunnel::gracefulRecoverChannel(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  
  LOGF_I("SSH", "Channel %d: Attempting graceful recovery", channelIndex);
  
  // 1. Vérifier l'état des sockets/canaux sans les fermer immédiatement
  bool localSocketOk = (ch.localSocket >= 0);
  bool sshChannelOk = (ch.channel != nullptr && !libssh2_channel_eof(ch.channel));
  
  if (localSocketOk) {
    int sockError = 0;
    socklen_t errLen = sizeof(sockError);
    if (getsockopt(ch.localSocket, SOL_SOCKET, SO_ERROR, &sockError, &errLen) == 0 && sockError != 0) {
      localSocketOk = false;
      LOGF_I("SSH", "Channel %d: Local socket has error: %s", channelIndex, strerror(sockError));
    }
  }
  
  // 2. Essayer de transmettre les données restantes si au moins un côté fonctionne
  if (localSocketOk || sshChannelOk) {
    LOGF_I("SSH", "Channel %d: Attempting to flush remaining data (local=%d, ssh=%d)", 
           channelIndex, localSocketOk, sshChannelOk);
    
    // Essayer de vider les buffers plusieurs fois
    for (int retry = 0; retry < 5; retry++) {
      size_t localBytes = ch.sshToLocalBuffer ? ch.sshToLocalBuffer->size() : 0;
      size_t sshBytes = ch.localToSshBuffer ? ch.localToSshBuffer->size() : 0;
      
      if (localBytes == 0 && sshBytes == 0) {
        LOGF_I("SSH", "Channel %d: All data flushed successfully", channelIndex);
        break;
      }
      
      // Essayer de traiter les données restantes
      processPendingData(channelIndex);
      
      vTaskDelay(pdMS_TO_TICKS(100)); // Attendre 100ms entre les tentatives
    }
  }
  
  // 3. Reset partiel des compteurs d'erreurs pour donner une chance
  if (ch.consecutiveErrors > 0) {
    ch.consecutiveErrors = ch.consecutiveErrors / 2; // Réduire de moitié au lieu de reset complet
    LOGF_I("SSH", "Channel %d: Reduced consecutive errors to %d", channelIndex, ch.consecutiveErrors);
  }
  
  ch.eagainErrors = 0; // Reset des erreurs EAGAIN
  ch.flowControlPaused = false;
  
  // 4. Mettre à jour l'activité
  ch.lastActivity = millis();
  
  LOGF_I("SSH", "Channel %d: Graceful recovery completed", channelIndex);
}

