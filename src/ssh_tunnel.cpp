#include "ssh_tunnel.h"
#include "lwip/sockets.h"
#include "memory_fixes.h"
#include "network_optimizations.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctype.h>
#include <errno.h>

// Define buffer size for data chunks
#define SSH_BUFFER_SIZE 1024

// Flow-control thresholds: use class-level constants from SSHTunnel (48KB/24KB)
// Note: remove local macro overrides to avoid divergence from header values.

#ifndef STUCK_PROBE_THRESHOLD
#define STUCK_PROBE_THRESHOLD                                                  \
  8 // consecutive failed probes before gracefulClosing
#endif

#ifndef SOCKET_RECV_BURST_THRESHOLD
#define SOCKET_RECV_BURST_THRESHOLD                                            \
  5 // consecutive -43 before marking terminal failure
#endif
#ifndef SOCKET_RECV_BURST_WINDOW_MS
#define SOCKET_RECV_BURST_WINDOW_MS 4000 // window to consider burst persistent
#endif
#ifndef SESSION_SOCKET_RECV_FAILURE_THRESHOLD
#define SESSION_SOCKET_RECV_FAILURE_THRESHOLD                                  \
  2 // channels failing terminally before session reset
#endif
#ifndef SESSION_FAILURE_WINDOW_MS
#define SESSION_FAILURE_WINDOW_MS 10000 // 10s window for session escalation
#endif

// SSH write parameters now defined as static constexpr members of SSHTunnel
// (see header)

// Session-level tracking for socket recv terminal failures is per instance.

// Channel integrity threshold (total queued cap across both directions)
#define MAX_QUEUED_BYTES (128 * 1024)

static const unsigned long kGlobalStallResetMs = 15000;
static const unsigned long kGlobalStallResetCooldownMs = 30000;
static const unsigned long kBufferOverloadStallMs = 15000;

static const size_t kInteractiveQueueThreshold = 4 * 1024;
static const unsigned long kInteractiveActivityWindowMs = 800;

// Health/recovery tuning (reduce noisy recoveries and WARN spam)
#ifndef HEALTH_UNHEALTHY_THRESHOLD
#define HEALTH_UNHEALTHY_THRESHOLD                                             \
  3 // consecutive unhealthy checks before hard recovery
#endif
#ifndef RECOVERY_COOLDOWN_MS
#define RECOVERY_COOLDOWN_MS                                                   \
  3000 // min delay between hard recoveries per channel
#endif
#ifndef HEALTH_WARN_THROTTLE_MS
#define HEALTH_WARN_THROTTLE_MS 5000 // rate-limit health WARN logs per channel
#endif

SSHTunnel::SSHTunnel()
    : session(nullptr), socketfd(-1), state(TUNNEL_DISCONNECTED),
      lastKeepAlive(0), lastConnectionAttempt(0), reconnectAttempts(0),
      keepAliveSocketSendFailures(0), bytesReceived(0), bytesSent(0),
      droppedBytes(0), channels(nullptr), rxBuffer(nullptr), txBuffer(nullptr),
      tunnelMutex(nullptr), statsMutex(nullptr), sessionMutex(nullptr),
      throttleMutex(nullptr), pendingConnectionsMutex(nullptr),
      config(&globalSSHConfig), libssh2Initialized(false),
      dataProcessingTask(nullptr), dataProcessingSemaphore(nullptr),
      dataProcessingTaskRunning(false), globalRateLimitBytesPerSec(0),
      globalBurstBytes(0), globalTokens(0), lastGlobalRefillMs(0),
      globalThrottleActive(false), lastGlobalThrottleLogMs(0),
      terminalSocketFailuresRecent(0), firstTerminalFailureMs(0),
      sessionResetTriggered(false), boundPort(-1), ringBufferCapacity(0),
      eventHandlers() {

  //   Use mutexes instead of binary semaphores for better performance
  tunnelMutex = xSemaphoreCreateMutex();
  statsMutex = xSemaphoreCreateMutex();
  sessionMutex = xSemaphoreCreateMutex();
  throttleMutex = xSemaphoreCreateMutex();
  pendingConnectionsMutex = xSemaphoreCreateMutex();
  dataProcessingSemaphore = xSemaphoreCreateBinary();

  if (tunnelMutex == NULL || statsMutex == NULL || sessionMutex == NULL ||
      throttleMutex == NULL || pendingConnectionsMutex == NULL ||
      dataProcessingSemaphore == NULL) {
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
  SAFE_DELETE_SEMAPHORE(sessionMutex);
  SAFE_DELETE_SEMAPHORE(throttleMutex);
  SAFE_DELETE_SEMAPHORE(pendingConnectionsMutex);
  SAFE_DELETE_SEMAPHORE(dataProcessingSemaphore);

  // Clean pending connections
  for (auto &pending : pendingConnections) {
    if (pending.channel) {
      closeLibssh2Channel(pending.channel);
    }
  }
  pendingConnections.clear();

  // Free dynamically allocated memory with ring buffers
  if (channels != nullptr) {
    for (int i = 0; i < config->getConnectionConfig().maxChannels; i++) {
      //   Clean unified buffers
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

  ringBufferCapacity = 0;

  if (libssh2Initialized) {
    libssh2_exit();
    libssh2Initialized = false;
  }
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
  const ConnectionConfig &connConfInit = config->getConnectionConfig();
  int maxChannels = connConfInit.maxChannels;
  size_t channelsSize = sizeof(TunnelChannel) * maxChannels;
  channels = (TunnelChannel *)safeMalloc(channelsSize, "SSH_CHANNELS");
  if (channels == nullptr) {
    LOG_E("SSH", "Failed to allocate memory for channels");
    unlockTunnel();
    return false;
  }
  memset(channels, 0, channelsSize);

  size_t ringBufferSize = getConfiguredRingBufferSize();
  ringBufferCapacity = ringBufferSize;
  LOGF_I("SSH", "Configuring %d channels with ring buffers of %u bytes",
         maxChannels, (unsigned)ringBufferSize);

  // Initialize channels with ring buffers
  for (int i = 0; i < maxChannels; i++) {
    channels[i].channel = nullptr;
    channels[i].localSocket = -1;
    channels[i].active = false;
    channels[i].lastActivity = 0;
    channels[i].pendingBytes = 0;
    channels[i].flowControlPaused = false;
    channels[i].localReadPaused = false;

    // Initialize new reliability-related fields
    channels[i].totalBytesReceived = 0;
    channels[i].totalBytesSent = 0;
    channels[i].lastSuccessfulWrite = 0;
    channels[i].lastSuccessfulRead = 0;
    channels[i].priority = connConfInit.defaultChannelPriority;
    channels[i].effectivePriority = channels[i].priority;
    channels[i].gracefulClosing = false;
    channels[i].consecutiveErrors = 0;
    channels[i].eagainErrors = 0;      // Separate counter for EAGAIN
    channels[i].readMutexFailures = 0; // Initialize new failure counters
    channels[i].writeMutexFailures = 0;
    channels[i].queuedBytesToLocal = 0;
    channels[i].queuedBytesToRemote = 0;
    channels[i].remoteEof = false;
    channels[i].lostWriteChunks = 0;
    channels[i].bytesDropped = 0;

    // Initialize large-transfer detection variables
    channels[i].largeTransferInProgress = false;
    channels[i].transferStartTime = 0;
    channels[i].transferredBytes = 0;
    channels[i].peakBytesPerSecond = 0;
    channels[i].socketRecvErrors = 0;
    channels[i].fatalCryptoErrors = 0;
    channels[i].lastWriteErrorMs = 0;
    channels[i].lastErrorDetailLogMs = 0;
    channels[i].stuckProbeCount = 0;
    channels[i].socketRecvBurstCount = 0;
    channels[i].firstSocketRecvErrorMs = 0;
    channels[i].terminalSocketFailure = false;
    channels[i].readProbeFailCount = 0;
    channels[i].writeProbeFailCount = 0;
    channels[i].localReadTerminated = false;

    //   Create unified buffers (simpler & efficient)
    char ringName[32];

    // Unified buffer for SSH->Local (configurable size)
    snprintf(ringName, sizeof(ringName), "CH%d_SSH2LOC", i);
    channels[i].sshToLocalBuffer = new DataRingBuffer(ringBufferSize, ringName);

    // Unified buffer for Local->SSH (configurable size)
    snprintf(ringName, sizeof(ringName), "CH%d_LOC2SSH", i);
    channels[i].localToSshBuffer = new DataRingBuffer(ringBufferSize, ringName);

    if (!channels[i].sshToLocalBuffer || !channels[i].localToSshBuffer) {
      LOGF_E("SSH", "Failed to create unified buffers for channel %d", i);
      cleanupPartialInit(maxChannels);
      unlockTunnel();
      return false;
    }

    //   Create mutexes instead of binary semaphores
    channels[i].readMutex = xSemaphoreCreateMutex();
    channels[i].writeMutex = xSemaphoreCreateMutex();

    if (channels[i].readMutex == NULL || channels[i].writeMutex == NULL) {
      LOGF_E("SSH", "Failed to create mutexes for channel %d", i);
      cleanupPartialInit(maxChannels);
      unlockTunnel();
      return false;
    }

    //   init deferred residual buffers (partial enqueue protection)
    channels[i].deferredToLocal = nullptr;
    channels[i].deferredToLocalSize = 0;
    channels[i].deferredToLocalOffset = 0;
    channels[i].deferredToRemote = nullptr;
    channels[i].deferredToRemoteSize = 0;
    channels[i].deferredToRemoteOffset = 0;
  }

  // Allocate RX/TX buffers (match ring buffer capacity)
  rxBuffer = (uint8_t *)safeMalloc(ringBufferSize, "SSH_RX_BUFFER");
  txBuffer = (uint8_t *)safeMalloc(ringBufferSize, "SSH_TX_BUFFER");

  globalRateLimitBytesPerSec = connConfInit.globalRateLimitBytesPerSec;
  globalBurstBytes = connConfInit.globalBurstBytes;
  initializeGlobalThrottle();

  if (rxBuffer == nullptr || txBuffer == nullptr) {
    LOG_E("SSH", "Failed to allocate memory for buffers");
    cleanupPartialInit(maxChannels);
    unlockTunnel();
    return false;
  }

  // Initialize libssh2
  int rc = libssh2_init(0);
  if (rc != 0) {
    LOGF_E("SSH", "libssh2 initialization failed: %d", rc);
    cleanupPartialInit(maxChannels);
    unlockTunnel();
    return false;
  }
  libssh2Initialized = true;

  //   Start dedicated data processing task
  if (!startDataProcessingTask()) {
    LOG_E("SSH", "Failed to start data processing task");
    cleanupPartialInit(maxChannels);
    unlockTunnel();
    return false;
  }

  LOG_I("SSH",
        "SSH tunnel initialized with optimized buffers and dedicated task");
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
    cleanupSSH();
    if (socketfd >= 0) {
      close(socketfd);
      socketfd = -1;
    }
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
  keepAliveSocketSendFailures = 0;

  if (listeners.empty()) {
    LOG_W("SSH", "Reverse tunnel established without active listeners");
  } else {
    for (size_t i = 0; i < listeners.size(); ++i) {
      const ListenerEntry &entry = listeners[i];
      LOGF_I("SSH", "Reverse tunnel #%u: %s:%d (bound %d) -> %s:%d",
             (unsigned)i, entry.mapping.remoteBindHost.c_str(),
             entry.mapping.remoteBindPort, entry.boundPort,
             entry.mapping.localHost.c_str(), entry.mapping.localPort);
    }
  }

  emitSessionConnected();

  return true;
}

void SSHTunnel::disconnect() {
  LOG_I("SSH", "Disconnecting SSH tunnel...");
  bool wasConnected = (state == TUNNEL_CONNECTED);

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
  keepAliveSocketSendFailures = 0;
  if (wasConnected) {
    emitSessionDisconnected();
  }

  LOG_I("SSH", "SSH tunnel disconnected");
}

bool SSHTunnel::isConnected() { return state == TUNNEL_CONNECTED; }

void SSHTunnel::loop() {
  unsigned long now = millis();

  // Scheduled session escalation due to terminal -43 bursts
  if (sessionResetTriggered && state == TUNNEL_CONNECTED) {
    LOG_W("SSH",
          "Loop: executing scheduled session reset (terminal -43 bursts)");
    disconnect();
    sessionResetTriggered = false;
    terminalSocketFailuresRecent = 0;
    firstTerminalFailureMs = 0;
    // Immediate reconnection will be handled by existing logic
    // (state==DISCONNECTED)
  }
  // Reset burst window if delay exceeded (prevents endless accumulation)
  if (terminalSocketFailuresRecent > 0 &&
      (now - firstTerminalFailureMs) > SESSION_FAILURE_WINDOW_MS) {
    terminalSocketFailuresRecent = 0;
    firstTerminalFailureMs = 0;
  }

  // Handle reconnection if needed (after any scheduled reset)
  bool connectionHealthy = true;
  if (state == TUNNEL_CONNECTED) {
    connectionHealthy = checkConnection();
    if (!connectionHealthy) {
      LOG_W("SSH", "Loop: SO_ERROR signalled, scheduling reconnection");
    }
  }

  if (state == TUNNEL_ERROR || !connectionHealthy) {
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
    if (state != TUNNEL_CONNECTED) {
      return;
    }
  }

  //   Reduce log frequency in the hot loop
  // Periodic statistics (every 5 minutes instead of 2)
  static unsigned long lastStatsTime = 0;
  if (now - lastStatsTime > 300000) { // 5 minutes
    printChannelStatistics();
    lastStatsTime = now;
  }

  //   Deadlock check every 30 seconds (reduced frequency)
  static unsigned long lastDeadlockCheck = 0;
  if (now - lastDeadlockCheck > 30000) { // 30 seconds
    checkAndRecoverDeadlocks();
    lastDeadlockCheck = now;
  }

  // Handle new connections
  handleNewConnection();

  //   Process pending connections only if no large transfer is active
  if (!isLargeTransferActive()) {
    processPendingConnections();
  }

  // Handle data for existing channels with weighted prioritization
  int maxChannels = config->getConnectionConfig().maxChannels;
  std::vector<ChannelScheduleEntry> lowBucket;
  std::vector<ChannelScheduleEntry> normalBucket;
  std::vector<ChannelScheduleEntry> highBucket;
  lowBucket.reserve(maxChannels);
  normalBucket.reserve(maxChannels);
  highBucket.reserve(maxChannels);

  bool hasWorkSignal = false;
  prepareChannelSchedule(lowBucket, normalBucket, highBucket, false,
                         hasWorkSignal);

  if (hasWorkSignal && dataProcessingSemaphore) {
    xSemaphoreGive(dataProcessingSemaphore);
  }

  auto processBucket = [&](const std::vector<ChannelScheduleEntry> &bucket) {
    if (bucket.empty()) {
      return;
    }

    uint8_t maxWeight = 0;
    for (const auto &entry : bucket) {
      if (entry.weight > maxWeight) {
        maxWeight = entry.weight;
      }
    }

    for (uint8_t pass = 0; pass < maxWeight; ++pass) {
      for (const auto &entry : bucket) {
        if (pass >= entry.weight) {
          continue;
        }

        int idx = entry.index;
        if (idx < 0 || idx >= maxChannels) {
          continue;
        }
        if (!channels[idx].active) {
          continue;
        }

        if (pass > 0 && !channelHasPendingWork(channels[idx])) {
          continue;
        }

        handleChannelData(idx);
      }
    }
  };

  processBucket(highBucket);
  processBucket(normalBucket);
  processBucket(lowBucket);

  // Cleanup inactive channels
  cleanupInactiveChannels();

  //   Slightly increase delay to reduce CPU contention
  vTaskDelay(pdMS_TO_TICKS(10)); // 10ms instead of 5ms
}

bool SSHTunnel::initializeSSH() {
  struct sockaddr_in sin;
  int rc = 0;
  socketfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socketfd == -1) {
    LOGF_E("SSH", "Error opening socket");
    return false;
  }

  // Optimize the SSH socket for better performance
  if (!NetworkOptimizer::optimizeSSHSocket(socketfd)) {
    LOGF_W("SSH", "Warning: Could not apply all socket optimizations");
  }

  // Use SSH configuration
  const SSHServerConfig &sshConfig = config->getSSHConfig();

  sin.sin_family = AF_INET;
  struct hostent *he = gethostbyname(sshConfig.host.c_str());
  if (he == nullptr) {
    LOGF_E("SSH", "Invalid remote hostname: %s", sshConfig.host.c_str());
    close(socketfd);
    socketfd = -1;
    return false;
  }
  memcpy(&sin.sin_addr, he->h_addr_list[0], he->h_length);
  sin.sin_port = htons(sshConfig.port); /* SSH port */
  if (connect(socketfd, (struct sockaddr *)(&sin),
              sizeof(struct sockaddr_in)) != 0) {
    LOGF_E("SSH", "Failed to connect!");
    close(socketfd);
    socketfd = -1;
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
  if (!lockSession(pdMS_TO_TICKS(5000))) {
    LOG_E("SSH", "Session lock timeout during handshake");
    return false;
  }
  rc = libssh2_session_handshake(session, socketfd);
  unlockSession();
  if (rc) {
    LOGF_E("SSH", "Error when starting up SSH session: %d", rc);
    return false;
  }

  const ConnectionConfig &connectionConfig = config->getConnectionConfig();
  if (connectionConfig.libssh2KeepAliveEnabled) {
    if (lockSession(pdMS_TO_TICKS(200))) {
      libssh2_keepalive_config(session, 1,
                               connectionConfig.libssh2KeepAliveIntervalSec);
      unlockSession();
      LOGF_I("SSH", "libssh2 keepalive configured (interval=%ds)",
             connectionConfig.libssh2KeepAliveIntervalSec);
    } else {
      LOG_W("SSH", "Session lock timeout while configuring libssh2 keepalive");
    }
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

static String encodeFingerprintHex(const unsigned char *data, size_t len) {
  static const char kHexDigits[] = "0123456789abcdef";
  String out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    unsigned char value = data[i];
    out += kHexDigits[(value >> 4) & 0x0F];
    out += kHexDigits[value & 0x0F];
  }
  return out;
}

static String encodeFingerprintBase64(const unsigned char *data, size_t len) {
  static const char kBase64Table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  String out;
  out.reserve(((len + 2) / 3) * 4);

  size_t index = 0;
  while (index < len) {
    uint32_t octet_a = data[index++];
    uint32_t octet_b = 0;
    uint32_t octet_c = 0;
    bool have_b = false;
    bool have_c = false;

    if (index < len) {
      octet_b = data[index++];
      have_b = true;
    }
    if (index < len) {
      octet_c = data[index++];
      have_c = true;
    }

    uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

    out += kBase64Table[(triple >> 18) & 0x3F];
    out += kBase64Table[(triple >> 12) & 0x3F];
    out += have_b ? kBase64Table[(triple >> 6) & 0x3F] : '=';
    out += have_c ? kBase64Table[triple & 0x3F] : '=';
  }

  while (out.length() > 0 && out.charAt(out.length() - 1) == '=') {
    out.remove(out.length() - 1);
  }
  return out;
}

static bool isValidHexFingerprint(const String &value) {
  if (value.length() != 64) {
    return false;
  }
  for (size_t i = 0; i < value.length(); ++i) {
    char c = value.charAt(i);
    if (!isxdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  return true;
}

bool SSHTunnel::verifyHostKey() {
  const SSHServerConfig &sshConfig = config->getSSHConfig();

  if (!sshConfig.verifyHostKey) {
    LOG_W("SSH", "Host key verification disabled - connection accepted without "
                 "verification");
    return true;
  }

  size_t host_key_len = 0;
  int host_key_type = 0;
  if (!lockSession(pdMS_TO_TICKS(200))) {
    LOG_E("SSH", "Session lock timeout while reading host key");
    return false;
  }
  const char *host_key =
      libssh2_session_hostkey(session, &host_key_len, &host_key_type);
  const unsigned char *fingerprint_raw =
      reinterpret_cast<const unsigned char *>(
          libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256));
  unlockSession();

  if (!host_key || host_key_len == 0) {
    LOG_E("SSH", "Failed to get host key from server");
    return false;
  }
  if (!fingerprint_raw) {
    LOG_E("SSH", "Failed to get host key fingerprint");
    return false;
  }

  String fingerprintHex = encodeFingerprintHex(fingerprint_raw, 32);
  String fingerprintBase64 = encodeFingerprintBase64(fingerprint_raw, 32);
  String fingerprintOpenSSH = String("SHA256:") + fingerprintBase64;

  String keyTypeStr;
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
  LOGF_I("SSH", "Server fingerprint (SHA256 hex): %s", fingerprintHex.c_str());
  LOGF_I("SSH", "Server fingerprint (OpenSSH): %s", fingerprintOpenSSH.c_str());

  if (sshConfig.hostKeyType.length() > 0 &&
      sshConfig.hostKeyType != keyTypeStr) {
    LOGF_E("SSH", "Host key type mismatch! Expected: %s, Got: %s",
           sshConfig.hostKeyType.c_str(), keyTypeStr.c_str());
    return false;
  }

  if (sshConfig.expectedHostKeyFingerprint.length() == 0) {
    LOG_W("SSH", "No expected fingerprint configured - accepting and storing "
                 "current fingerprint");
    LOGF_I("SSH", "Store this fingerprint (hex): %s", fingerprintHex.c_str());
    LOGF_I("SSH", "Store this fingerprint (OpenSSH): %s",
           fingerprintOpenSSH.c_str());
    return true;
  }

  String expectedRaw = sshConfig.expectedHostKeyFingerprint;
  expectedRaw.trim();
  expectedRaw.replace("\r", "");
  expectedRaw.replace("\n", "");

  bool expectedIsBase64 = false;
  String expectedComparable;

  String lowered = expectedRaw;
  lowered.toLowerCase();
  if (lowered.startsWith("sha256:")) {
    expectedIsBase64 = true;
    expectedComparable = expectedRaw.substring(expectedRaw.indexOf(':') + 1);
  } else {
    String candidate = expectedRaw;
    candidate.replace(" ", "");
    candidate.replace(":", "");
    String candidateLower = candidate;
    candidateLower.toLowerCase();
    if (isValidHexFingerprint(candidateLower)) {
      expectedComparable = candidateLower;
    } else {
      expectedIsBase64 = true;
      expectedComparable = expectedRaw;
    }
  }

  if (expectedIsBase64) {
    expectedComparable.trim();
    if (expectedComparable.startsWith("SHA256:")) {
      expectedComparable.remove(0, 7);
    } else if (expectedComparable.startsWith("sha256:")) {
      expectedComparable.remove(0, 7);
    }
    expectedComparable.replace(" ", "");
    expectedComparable.replace("\r", "");
    expectedComparable.replace("\n", "");
    expectedComparable.replace("=", "");
  } else {
    expectedComparable.toLowerCase();
    expectedComparable.replace(" ", "");
    expectedComparable.replace(":", "");
  }

  bool fingerprintsMatch = expectedIsBase64
                               ? (expectedComparable == fingerprintBase64)
                               : (expectedComparable == fingerprintHex);

  if (!fingerprintsMatch) {
    LOG_E("SSH", "HOST KEY VERIFICATION FAILED!");
    LOG_E("SSH", "This could indicate a Man-in-the-Middle attack!");
    if (expectedIsBase64) {
      LOGF_E("SSH", "Expected (OpenSSH): SHA256:%s",
             expectedComparable.c_str());
      LOGF_E("SSH", "Got      (OpenSSH): %s", fingerprintOpenSSH.c_str());
    } else {
      LOGF_E("SSH", "Expected (hex): %s", expectedComparable.c_str());
      LOGF_E("SSH", "Got      (hex): %s", fingerprintHex.c_str());
    }
    LOGF_E("SSH", "Key type: %s", keyTypeStr.c_str());

    if (sshConfig.onHostKeyMismatch) {
      const String actualForCallback =
          expectedIsBase64 ? fingerprintOpenSSH : fingerprintHex;
      sshConfig.onHostKeyMismatch(expectedRaw, actualForCallback, keyTypeStr,
                                  sshConfig.hostKeyMismatchContext);
    }
    return false;
  }

  LOG_I("SSH", "Host key verification successful");
  return true;
}

bool SSHTunnel::authenticateSSH() {
  // Use SSH configuration
  const SSHServerConfig &sshConfig = config->getSSHConfig();

  /* check what authentication methods are available */
  char *userauthlist = nullptr;
  if (lockSession(pdMS_TO_TICKS(500))) {
    userauthlist = libssh2_userauth_list(session, sshConfig.username.c_str(),
                                         sshConfig.username.length());
    unlockSession();
  } else {
    LOG_E("SSH", "Session lock timeout while querying authentication methods");
    return false;
  }
  if (userauthlist == nullptr) {
    String detail = "";
    if (lockSession(pdMS_TO_TICKS(200))) {
      char *errmsg = nullptr;
      int errlen = 0;
      libssh2_session_last_error(session, &errmsg, &errlen, 0);
      if (errmsg && errlen > 0) {
        detail = String(errmsg).substring(0, errlen);
      }
      unlockSession();
    }
    if (detail.length() > 0) {
      LOGF_E("SSH", "Failed to query authentication methods: %s",
             detail.c_str());
    } else {
      LOG_E("SSH", "Failed to query authentication methods (no data returned)");
    }
    return false;
  }
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
    int authRc = 0;
    if (lockSession(pdMS_TO_TICKS(1000))) {
      authRc = libssh2_userauth_password(session, sshConfig.username.c_str(),
                                         sshConfig.password.c_str());
      unlockSession();
    } else {
      LOG_E("SSH", "Session lock timeout during password authentication");
      return false;
    }
    if (authRc) {
      LOG_E("SSH", "Authentication by password failed");
      return false;
    }
    LOG_I("SSH", "Authentication by password succeeded");
  } else if (auth & AUTH_PUBLICKEY) {
    // Diagnose keys before authentication
    config->diagnoseSSHKeys();

    // Check if keys are already loaded in memory
    if (sshConfig.privateKeyData.length() > 0 &&
        sshConfig.publicKeyData.length() > 0) {
      // Validate keys before attempting authentication
      if (!config->validateSSHKeys()) {
        LOG_E("SSH", "SSH keys validation failed");
        return false;
      }

      // Use libssh2_userauth_publickey_frommemory
      LOGF_I("SSH",
             "Authenticating with keys from memory (private: %d bytes, public: "
             "%d bytes)",
             sshConfig.privateKeyData.length(),
             sshConfig.publicKeyData.length());

      const char *passphrase = sshConfig.password.length() > 0
                                   ? sshConfig.password.c_str()
                                   : nullptr;

      LOGF_D("SSH", "Using passphrase: %s", passphrase ? "yes" : "no");

      int auth_result = 0;
      String errorDetail = "";
      if (lockSession(pdMS_TO_TICKS(1000))) {
        auth_result = libssh2_userauth_publickey_frommemory(
            session, sshConfig.username.c_str(), sshConfig.username.length(),
            sshConfig.publicKeyData.c_str(), sshConfig.publicKeyData.length(),
            sshConfig.privateKeyData.c_str(), sshConfig.privateKeyData.length(),
            passphrase);
        if (auth_result) {
          char *errmsg = nullptr;
          int errlen = 0;
          libssh2_session_last_error(session, &errmsg, &errlen, 0);
          if (errmsg && errlen > 0) {
            errorDetail = String(errmsg).substring(0, errlen);
          }
        }
        unlockSession();
      } else {
        LOG_E("SSH", "Session lock timeout during public key authentication");
        return false;
      }
      if (auth_result) {
        const char *detail =
            errorDetail.length() ? errorDetail.c_str() : "Unknown";
        LOGF_E("SSH",
               "Authentication by public key from memory failed! Error code: "
               "%d, Message: %s",
               auth_result, detail);

        // Retry with explicit empty passphrase
        LOGF_I("SSH", "Retrying with empty passphrase...");
        errorDetail = "";
        if (lockSession(pdMS_TO_TICKS(1000))) {
          auth_result = libssh2_userauth_publickey_frommemory(
              session, sshConfig.username.c_str(), sshConfig.username.length(),
              sshConfig.publicKeyData.c_str(), sshConfig.publicKeyData.length(),
              sshConfig.privateKeyData.c_str(),
              sshConfig.privateKeyData.length(), "");
          if (auth_result) {
            char *errmsg = nullptr;
            int errlen = 0;
            libssh2_session_last_error(session, &errmsg, &errlen, 0);
            if (errmsg && errlen > 0) {
              errorDetail = String(errmsg).substring(0, errlen);
            }
          }
          unlockSession();
        } else {
          LOG_E("SSH", "Session lock timeout during public key retry");
          return false;
        }
        if (auth_result) {
          const char *retryDetail =
              errorDetail.length() ? errorDetail.c_str() : "Unknown";
          LOGF_E(
              "SSH",
              "Retry with empty passphrase also failed! Error: %d, Message: %s",
              auth_result, retryDetail);

          // Final attempt: try NULL instead of empty string
          LOGF_I("SSH", "Final retry with NULL passphrase...");
          errorDetail = "";
          if (lockSession(pdMS_TO_TICKS(1000))) {
            auth_result = libssh2_userauth_publickey_frommemory(
                session, sshConfig.username.c_str(),
                sshConfig.username.length(), sshConfig.publicKeyData.c_str(),
                sshConfig.publicKeyData.length(),
                sshConfig.privateKeyData.c_str(),
                sshConfig.privateKeyData.length(), NULL);
            if (auth_result) {
              char *errmsg = nullptr;
              int errlen = 0;
              libssh2_session_last_error(session, &errmsg, &errlen, 0);
              if (errmsg && errlen > 0) {
                errorDetail = String(errmsg).substring(0, errlen);
              }
            }
            unlockSession();
          } else {
            LOG_E("SSH", "Session lock timeout during public key final retry");
            return false;
          }
          if (auth_result) {
            const char *finalDetail =
                errorDetail.length() ? errorDetail.c_str() : "Unknown";
            LOGF_E("SSH",
                   "All authentication attempts failed! Final error: %d, "
                   "Message: %s",
                   auth_result, finalDetail);

            // Info: supported formats hint
            LOG_W("SSH", "Note: Your private key is in OpenSSH format. "
                         "Consider converting to PEM format:");
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
      LOG_W("SSH", "SSH keys not available in memory, falling back to "
                   "file-based authentication");
      String keyfile1_str = sshConfig.privateKeyPath + ".pub";
      const char *keyfile1 = keyfile1_str.c_str();
      const char *keyfile2 = sshConfig.privateKeyPath.c_str();
      int fileAuth = 0;
      if (lockSession(pdMS_TO_TICKS(1000))) {
        fileAuth = libssh2_userauth_publickey_fromfile(
            session, sshConfig.username.c_str(), keyfile1, keyfile2,
            sshConfig.password.c_str());
        if (fileAuth) {
          char *errmsg = nullptr;
          int errlen = 0;
          libssh2_session_last_error(session, &errmsg, &errlen, 0);
          String detailStr = "";
          if (errmsg && errlen > 0) {
            detailStr = String(errmsg).substring(0, errlen);
          }
          unlockSession();
          const char *detail =
              detailStr.length() ? detailStr.c_str() : "Unknown";
          LOGF_E("SSH",
                 "Authentication by public key from file failed! Error: %d, "
                 "Message: %s",
                 fileAuth, detail);
          return false;
        }
        unlockSession();
      } else {
        LOG_E("SSH", "Session lock timeout during file-based authentication");
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
  cancelAllListeners();
  boundPort = -1;

  const std::vector<TunnelConfig> &mappings = config->getTunnelMappings();
  if (mappings.empty()) {
    LOG_E("SSH", "No tunnel mappings configured");
    return false;
  }

  int listenerLimit = config->getConnectionConfig().maxReverseListeners;
  int desired = std::min(listenerLimit, static_cast<int>(mappings.size()));
  if (desired <= 0) {
    LOG_E("SSH", "maxReverseListeners must be positive to create listeners");
    return false;
  }

  for (int i = 0; i < desired; ++i) {
    ListenerEntry entry;
    entry.mapping = mappings[i];
    if (!createListenerForMapping(entry.mapping, entry)) {
      LOGF_E("SSH",
             "Failed to create reverse listener for mapping %s:%d -> %s:%d",
             entry.mapping.remoteBindHost.c_str(), entry.mapping.remoteBindPort,
             entry.mapping.localHost.c_str(), entry.mapping.localPort);
      cancelAllListeners();
      return false;
    }
    listeners.push_back(entry);
    if (boundPort < 0) {
      boundPort = entry.boundPort;
    }
  }

  if (static_cast<int>(mappings.size()) > desired) {
    LOGF_W("SSH",
           "Only %d/%zu reverse listeners created due to "
           "maxReverseListeners limit",
           desired, mappings.size());
  }

  return !listeners.empty();
}

void SSHTunnel::cleanupSSH() {
  cancelAllListeners();
  boundPort = -1;

  if (session) {
    if (lockSession(pdMS_TO_TICKS(500))) {
      libssh2_session_disconnect(session, "Shutdown");
      libssh2_session_free(session);
      unlockSession();
    }
    session = nullptr;
  }
}

void SSHTunnel::closeLibssh2Channel(LIBSSH2_CHANNEL *channel) {
  if (!channel) {
    return;
  }
  if (lockSession(pdMS_TO_TICKS(200))) {
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);
    unlockSession();
  }
}

bool SSHTunnel::channelEofLocked(LIBSSH2_CHANNEL *channel) {
  if (!channel) {
    return true;
  }
  bool eof = false;
  if (lockSession(pdMS_TO_TICKS(200))) {
    eof = libssh2_channel_eof(channel);
    unlockSession();
  }
  return eof;
}

bool SSHTunnel::channelHasPendingWork(const TunnelChannel &channel) const {
  if (!channel.active) {
    return false;
  }

  if (channel.sshToLocalBuffer && !channel.sshToLocalBuffer->empty()) {
    return true;
  }
  if (channel.localToSshBuffer && !channel.localToSshBuffer->empty()) {
    return true;
  }
  if (channel.deferredToLocal &&
      channel.deferredToLocalOffset < channel.deferredToLocalSize) {
    return true;
  }
  if (channel.deferredToRemote &&
      channel.deferredToRemoteOffset < channel.deferredToRemoteSize) {
    return true;
  }
  if (channel.pendingBytes > 0) {
    return true;
  }

  return false;
}

void SSHTunnel::initializeGlobalThrottle() {
  bool locked = lockThrottle(pdMS_TO_TICKS(20));
  lastGlobalRefillMs = millis();
  lastGlobalThrottleLogMs = 0;
  globalThrottleActive = false;
  if (globalRateLimitBytesPerSec == 0) {
    globalTokens = 0;
    if (locked) {
      unlockThrottle();
    }
    return;
  }
  if (globalBurstBytes == 0) {
    globalBurstBytes = globalRateLimitBytesPerSec;
  }
  globalTokens = globalBurstBytes;
  if (locked) {
    unlockThrottle();
  }
}

void SSHTunnel::refillGlobalTokens() {
  if (globalRateLimitBytesPerSec == 0) {
    return;
  }
  unsigned long now = millis();
  unsigned long elapsed = now - lastGlobalRefillMs;
  if (elapsed == 0) {
    return;
  }
  uint64_t add = ((uint64_t)globalRateLimitBytesPerSec * elapsed) / 1000ULL;
  if (add > 0) {
    size_t cap =
        globalBurstBytes ? globalBurstBytes : globalRateLimitBytesPerSec;
    uint64_t newTotal = (uint64_t)globalTokens + add;
    if (newTotal > cap) {
      globalTokens = cap;
    } else {
      globalTokens = (size_t)newTotal;
    }
    lastGlobalRefillMs = now;
  }
}

size_t SSHTunnel::getGlobalAllowance(size_t desired) {
  if (globalRateLimitBytesPerSec == 0 || desired == 0) {
    return desired;
  }
  if (throttleMutex == NULL) {
    return desired;
  }
  if (!lockThrottle(pdMS_TO_TICKS(5))) {
    return 0;
  }
  refillGlobalTokens();
  size_t available = globalTokens;
  if (available == 0) {
    unsigned long now = millis();
    if (!globalThrottleActive || (now - lastGlobalThrottleLogMs) > 1000) {
      lastGlobalThrottleLogMs = now;
      LOGF_W("SSH", "Global throttle active (requested=%zu, rate=%zu B/s)",
             desired, globalRateLimitBytesPerSec);
    }
    globalThrottleActive = true;
    unlockThrottle();
    return 0;
  }
  globalThrottleActive = false;
  size_t allowed = (desired > available) ? available : desired;
  unlockThrottle();
  return allowed;
}

void SSHTunnel::commitGlobalTokens(size_t used) {
  if (globalRateLimitBytesPerSec == 0 || used == 0) {
    return;
  }
  if (!lockThrottle(pdMS_TO_TICKS(5))) {
    return;
  }
  if (used >= globalTokens) {
    globalTokens = 0;
  } else {
    globalTokens -= used;
  }
  unlockThrottle();
}

bool SSHTunnel::createListenerForMapping(const TunnelConfig &mapping,
                                         ListenerEntry &entry) {
  const int maxlisten = std::max(1, config->getConnectionConfig().maxChannels);
  const char *bindHost = mapping.remoteBindHost.c_str();
  int bindPort = mapping.remoteBindPort;
  int boundPortResult = 0;
  LIBSSH2_LISTENER *handle = nullptr;
  const int maxAttempts = 50;
  int attempts = 0;

  while (!handle && attempts < maxAttempts) {
    ++attempts;
    if (!lockSession(pdMS_TO_TICKS(500))) {
      vTaskDelay(pdMS_TO_TICKS(10));
      continue;
    }
    handle = libssh2_channel_forward_listen_ex(session, bindHost, bindPort,
                                               &boundPortResult, maxlisten);
    unlockSession();
    if (!handle) {
      vTaskDelay(pdMS_TO_TICKS(10));
    }
  }

  if (!handle) {
    LOGF_E("SSH", "Unable to create reverse listener for %s:%d -> %s:%d",
           mapping.remoteBindHost.c_str(), mapping.remoteBindPort,
           mapping.localHost.c_str(), mapping.localPort);
    emitErrorEvent(-1, "Failed to create reverse listener");
    return false;
  }

  entry.listener = handle;
  entry.mapping = mapping;
  entry.boundPort = boundPortResult;
  LOGF_I("SSH", "Reverse listener ready %s:%d (bound %d) -> %s:%d",
         mapping.remoteBindHost.c_str(), mapping.remoteBindPort,
         boundPortResult, mapping.localHost.c_str(), mapping.localPort);
  return true;
}

void SSHTunnel::cancelListener(ListenerEntry &entry) {
  if (!entry.listener) {
    return;
  }
  if (lockSession(pdMS_TO_TICKS(500))) {
    libssh2_channel_forward_cancel(entry.listener);
    unlockSession();
  }
  entry.listener = nullptr;
}

void SSHTunnel::cancelAllListeners() {
  for (auto &entry : listeners) {
    cancelListener(entry);
  }
  listeners.clear();
  boundPort = -1;
}

int SSHTunnel::acquireChannelSlot() {
  if (!channels) {
    return -1;
  }
  int maxChannels = config->getConnectionConfig().maxChannels;
  unsigned long now = millis();
  for (int i = 0; i < maxChannels; ++i) {
    if (!channels[i].active) {
      LOGF_D("SSH", "Channel slot %d selected (inactive)", i);
      return i;
    }
  }

  for (int i = 0; i < maxChannels; ++i) {
    if (channels[i].active && (now - channels[i].lastActivity) > 30000) {
      LOGF_I("SSH", "Recycling inactive channel %d", i);
      closeChannel(i, ChannelCloseReason::Timeout);
      return i;
    }
  }

  return -1;
}

int SSHTunnel::connectToLocalEndpoint(const TunnelConfig &mapping) {
  int localSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (localSocket < 0) {
    LOG_E("SSH", "Failed to create local socket");
    emitErrorEvent(errno, "Failed to create local socket");
    return -1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(mapping.localPort);
  if (inet_pton(AF_INET, mapping.localHost.c_str(), &addr.sin_addr) != 1) {
    LOGF_E("SSH", "Invalid local host address %s", mapping.localHost.c_str());
    emitErrorEvent(-2, "Invalid local host address");
    close(localSocket);
    return -1;
  }

  if (::connect(localSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOGF_E("SSH", "Failed to connect to local endpoint %s:%d",
           mapping.localHost.c_str(), mapping.localPort);
    emitErrorEvent(errno, "Failed to connect to local endpoint");
    close(localSocket);
    return -1;
  }

  size_t localRcvBuf = getLowWaterLocal();
  if (localRcvBuf > 16 * 1024) {
    localRcvBuf = 16 * 1024;
  } else if (localRcvBuf < 4 * 1024) {
    localRcvBuf = 4 * 1024;
  }
  if (!NetworkOptimizer::optimizeSocket(localSocket,
                                        static_cast<int>(localRcvBuf))) {
    LOG_W("SSH", "Failed to optimize local socket");
  }

  int flags = fcntl(localSocket, F_GETFL, 0);
  fcntl(localSocket, F_SETFL, flags | O_NONBLOCK);
  return localSocket;
}

void SSHTunnel::snapshotEndpoint(TunnelChannel &channel,
                                 const TunnelConfig &mapping) {
  snprintf(channel.endpoint.localHost, SSH_TUNNEL_ENDPOINT_HOST_MAX, "%s",
           mapping.localHost.c_str());
  channel.endpoint.localPort = mapping.localPort;
  snprintf(channel.endpoint.remoteHost, SSH_TUNNEL_ENDPOINT_HOST_MAX, "%s",
           mapping.remoteBindHost.c_str());
  channel.endpoint.remotePort = mapping.remoteBindPort;
}

bool SSHTunnel::bindChannelToMapping(LIBSSH2_CHANNEL *channel,
                                     const TunnelConfig &mapping) {
  int channelIndex = acquireChannelSlot();
  if (channelIndex == -1) {
    LOGF_W("SSH",
           "No available channel slots (active: %d/%d), closing new connection",
           getActiveChannels(), config->getConnectionConfig().maxChannels);
    emitErrorEvent(-3, "No available channel slots");
    return false;
  }

  int localSocket = connectToLocalEndpoint(mapping);
  if (localSocket < 0) {
    return false;
  }

  TunnelChannel &slot = channels[channelIndex];
  slot.channel = channel;
  slot.localSocket = localSocket;
  slot.active = true;
  slot.lastActivity = millis();
  slot.pendingBytes = 0;
  slot.flowControlPaused = false;
  slot.localReadPaused = false;
  slot.priority = config->getConnectionConfig().defaultChannelPriority;
  slot.effectivePriority = slot.priority;
  slot.largeTransferInProgress = false;
  slot.transferStartTime = slot.lastActivity;
  slot.transferredBytes = 0;
  slot.peakBytesPerSecond = 0;
  slot.healthUnhealthyCount = 0;
  slot.lastHardRecoveryMs = 0;
  slot.lastHealthWarnMs = 0;
  slot.consecutiveErrors = 0;
  slot.eagainErrors = 0;
  slot.readMutexFailures = 0;
  slot.writeMutexFailures = 0;
  slot.queuedBytesToLocal = 0;
  slot.queuedBytesToRemote = 0;
  slot.remoteEof = false;
  slot.lostWriteChunks = 0;
  slot.bytesDropped = 0;
  slot.socketRecvErrors = 0;
  slot.fatalCryptoErrors = 0;
  slot.lastWriteErrorMs = 0;
  slot.lastErrorDetailLogMs = 0;
  slot.stuckProbeCount = 0;
  slot.socketRecvBurstCount = 0;
  slot.firstSocketRecvErrorMs = 0;
  slot.terminalSocketFailure = false;
  slot.readProbeFailCount = 0;
  slot.writeProbeFailCount = 0;
  slot.localReadTerminated = false;
  slot.gracefulClosing = false;
  snapshotEndpoint(slot, mapping);

  if (lockSession(pdMS_TO_TICKS(200))) {
    libssh2_channel_set_blocking(channel, 0);
    unlockSession();
  } else {
    LOGF_W("SSH",
           "Channel %d: Unable to switch to non-blocking mode (lock timeout)",
           channelIndex);
  }

  LOGF_I("SSH", "New tunnel connection channel %d (%s:%d -> %s:%d)",
         channelIndex, mapping.remoteBindHost.c_str(), mapping.remoteBindPort,
         mapping.localHost.c_str(), mapping.localPort);
  emitChannelOpened(channelIndex);
  return true;
}

void SSHTunnel::emitSessionConnected() {
  if (eventHandlers.onSessionConnected) {
    eventHandlers.onSessionConnected();
  }
}

void SSHTunnel::emitSessionDisconnected() {
  if (eventHandlers.onSessionDisconnected) {
    eventHandlers.onSessionDisconnected();
  }
}

void SSHTunnel::emitChannelOpened(int channelIndex) {
  if (eventHandlers.onChannelOpened) {
    eventHandlers.onChannelOpened(channelIndex);
  }
}

void SSHTunnel::emitChannelClosed(int channelIndex, ChannelCloseReason reason) {
  if (eventHandlers.onChannelClosed) {
    eventHandlers.onChannelClosed(channelIndex, reason);
  }
}

void SSHTunnel::emitErrorEvent(int code, const char *detail) {
  if (eventHandlers.onError) {
    eventHandlers.onError(code, detail);
  }
}

void SSHTunnel::emitChannelError(int channelIndex, TunnelErrorCode code,
                                 int rawCode, const char *detail) {
  if (!eventHandlers.onError || detail == nullptr) {
    return;
  }
  char message[200];
  if (channelIndex >= 0) {
    if (rawCode != 0) {
      snprintf(message, sizeof(message), "ch=%d code=%d raw=%d: %s",
               channelIndex, static_cast<int>(code), rawCode, detail);
    } else {
      snprintf(message, sizeof(message), "ch=%d code=%d: %s", channelIndex,
               static_cast<int>(code), detail);
    }
    emitErrorEvent(static_cast<int>(code), message);
  } else {
    emitErrorEvent(static_cast<int>(code), detail);
  }
}

void SSHTunnel::emitChannelWriteBroken(int channelIndex, TunnelErrorCode code,
                                       int rawCode, const char *detail) {
  if (eventHandlers.onChannelWriteBroken) {
    eventHandlers.onChannelWriteBroken(channelIndex, code, rawCode, detail);
  }
}

static TunnelErrorCode mapSshErrorToCode(int rc, bool isWrite) {
  switch (rc) {
  case LIBSSH2_ERROR_EAGAIN:
    return TunnelErrorCode::SshEagain;
  case LIBSSH2_ERROR_SOCKET_RECV:
    return TunnelErrorCode::SshSocketRecv;
  case LIBSSH2_ERROR_SOCKET_SEND:
    return TunnelErrorCode::SshSocketSend;
  case LIBSSH2_ERROR_CHANNEL_CLOSED:
    return TunnelErrorCode::SshChannelClosed;
  case LIBSSH2_ERROR_DECRYPT:
    return TunnelErrorCode::SshDecrypt;
  default:
    return isWrite ? TunnelErrorCode::SshWriteFailure
                   : TunnelErrorCode::SshReadFailure;
  }
}

void SSHTunnel::emitLargeTransferEvent(int channelIndex, bool started) {
  if (started) {
    if (eventHandlers.onLargeTransferStart) {
      eventHandlers.onLargeTransferStart(channelIndex);
    }
  } else {
    if (eventHandlers.onLargeTransferEnd) {
      eventHandlers.onLargeTransferEnd(channelIndex);
    }
  }
}

void SSHTunnel::recordTerminalSocketFailure(unsigned long now) {
  if (terminalSocketFailuresRecent == 0) {
    firstTerminalFailureMs = now;
  }
  terminalSocketFailuresRecent++;
  if (terminalSocketFailuresRecent >= SESSION_SOCKET_RECV_FAILURE_THRESHOLD &&
      (now - firstTerminalFailureMs) <= SESSION_FAILURE_WINDOW_MS) {
    if (!sessionResetTriggered) {
      sessionResetTriggered = true; // the loop() will handle it
      LOG_W("SSH", "Session escalation: multiple terminal -43 bursts -> "
                   "scheduling reconnect");
    }
  }
}

uint8_t SSHTunnel::getPriorityWeight(uint8_t priority) const {
  const ConnectionConfig &connConf = config->getConnectionConfig();
  switch (priority) {
  case 2:
    return connConf.priorityWeightHigh;
  case 1:
    return connConf.priorityWeightNormal;
  default:
    return connConf.priorityWeightLow;
  }
}

uint8_t SSHTunnel::evaluateChannelPriority(int channelIndex, unsigned long now,
                                           bool hasWork) const {
  if (channels == nullptr || channelIndex < 0 ||
      channelIndex >= config->getConnectionConfig().maxChannels) {
    return 0;
  }

  const TunnelChannel &ch = channels[channelIndex];
  uint8_t priority = ch.priority;

  bool recentRead =
      (ch.lastSuccessfulRead != 0) && (now >= ch.lastSuccessfulRead) &&
      ((now - ch.lastSuccessfulRead) <= kInteractiveActivityWindowMs);
  bool recentWrite =
      (ch.lastSuccessfulWrite != 0) && (now >= ch.lastSuccessfulWrite) &&
      ((now - ch.lastSuccessfulWrite) <= kInteractiveActivityWindowMs);
  bool interactiveActive = recentRead || recentWrite;
  bool queuesLight = (ch.queuedBytesToLocal <= kInteractiveQueueThreshold) &&
                     (ch.queuedBytesToRemote <= kInteractiveQueueThreshold);

  if (interactiveActive && queuesLight && hasWork) {
    if (priority < 2) {
      priority++;
    }
  }

  if (ch.largeTransferInProgress && priority > 0) {
    priority--;
  }

  if (ch.flowControlPaused && priority > 0) {
    priority--;
  }

  if (ch.terminalSocketFailure) {
    priority = 0;
  }

  if (ch.gracefulClosing && hasWork && priority < 1) {
    priority = 1;
  }

  if (priority > 2) {
    priority = 2;
  }

  return priority;
}

void SSHTunnel::prepareChannelSchedule(
    std::vector<ChannelScheduleEntry> &low,
    std::vector<ChannelScheduleEntry> &normal,
    std::vector<ChannelScheduleEntry> &high, bool onlyWithWork,
    bool &hasWorkSignal) {
  low.clear();
  normal.clear();
  high.clear();
  hasWorkSignal = false;

  if (channels == nullptr) {
    return;
  }

  const ConnectionConfig &connConf = config->getConnectionConfig();
  int maxChannels = connConf.maxChannels;
  unsigned long now = millis();

  for (int i = 0; i < maxChannels; ++i) {
    if (!channels[i].active) {
      continue;
    }

    TunnelChannel &ch = channels[i];
    bool pendingWork = channelHasPendingWork(ch);
    bool include = !onlyWithWork || pendingWork || ch.gracefulClosing;

    uint8_t effective =
        evaluateChannelPriority(i, now, pendingWork || ch.gracefulClosing);
    ch.effectivePriority = effective;

    if (!include) {
      continue;
    }

    if (pendingWork || ch.gracefulClosing) {
      hasWorkSignal = true;
    }

    uint8_t weight = getPriorityWeight(effective);
    if (!pendingWork && !ch.gracefulClosing) {
      weight = 1;
    }

    ChannelScheduleEntry entry{i, weight};
    if (effective >= 2) {
      high.push_back(entry);
    } else if (effective == 1) {
      normal.push_back(entry);
    } else {
      low.push_back(entry);
    }
  }
}

bool SSHTunnel::handleNewConnection() {
  bool acceptedAny = false;
  if (listeners.empty()) {
    return false;
  }

  for (auto &entry : listeners) {
    if (!entry.listener) {
      continue;
    }

    LIBSSH2_CHANNEL *channel = nullptr;
    if (lockSession(pdMS_TO_TICKS(200))) {
      channel = libssh2_channel_forward_accept(entry.listener);
      unlockSession();
    } else {
      continue;
    }

    if (!channel) {
      continue;
    }

    acceptedAny = true;

    if (!shouldAcceptNewConnection()) {
      LOGF_W("SSH",
             "All channels busy - rejecting new connection for mapping %s:%d",
             entry.mapping.remoteBindHost.c_str(),
             entry.mapping.remoteBindPort);
      closeLibssh2Channel(channel);
      continue;
    }

    if (!bindChannelToMapping(channel, entry.mapping)) {
      closeLibssh2Channel(channel);
    }
  }

  return acceptedAny;
}

void SSHTunnel::handleChannelData(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active || !ch.channel || ch.localSocket < 0) {
    return;
  }

  unsigned long now = millis();

  // Check channel health before processing data (with hysteresis and cooldown)
  if (!isChannelHealthy(channelIndex)) {
    // Cas terminal: isChannelHealthy already logged; handle immediate/timeout
    // close here
    if (ch.terminalSocketFailure) {
      unsigned long nowTerm = millis();
      bool buffersEmptyTerm =
          (ch.sshToLocalBuffer ? ch.sshToLocalBuffer->empty() : true) &&
          (ch.localToSshBuffer ? ch.localToSshBuffer->empty() : true);
      bool timeoutTerm = (ch.firstSocketRecvErrorMs &&
                          (nowTerm - ch.firstSocketRecvErrorMs) > 1500);
      if (buffersEmptyTerm || timeoutTerm) {
        LOGF_W(
            "SSH",
            "Channel %d: Closing (terminal burst) buffersEmpty=%d timeout=%d",
            channelIndex, buffersEmptyTerm ? 1 : 0, timeoutTerm ? 1 : 0);
        closeChannel(channelIndex);
      } else {
        // tenter un drain minimal
        processPendingData(channelIndex);
      }
      return;
    }
    ch.healthUnhealthyCount++;
    // Prefer a gentle approach first
    if (ch.healthUnhealthyCount < HEALTH_UNHEALTHY_THRESHOLD) {
      if (now - ch.lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
        LOGF_D("SSH",
               "Channel %d: Unhealthy #%d -> attempting graceful recovery",
               channelIndex, ch.healthUnhealthyCount);
        ch.lastHealthWarnMs = now;
      }
      gracefulRecoverChannel(channelIndex);
    } else {
      // Only allow a hard recovery after cooldown
      if (now - ch.lastHardRecoveryMs > RECOVERY_COOLDOWN_MS) {
        if (now - ch.lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
          LOGF_W("SSH",
                 "Channel %d: Unhealthy threshold reached -> hard recovery",
                 channelIndex);
          ch.lastHealthWarnMs = now;
        }
        recoverChannel(channelIndex);
        ch.lastHardRecoveryMs = now;
        ch.healthUnhealthyCount = 0; // reset after a hard attempt
      } else {
        if (now - ch.lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
          LOGF_I("SSH", "Channel %d: Skipping hard recovery (cooldown)",
                 channelIndex);
          ch.lastHealthWarnMs = now;
        }
      }
    }

    // Verify if recovery succeeded
    if (!isChannelHealthy(channelIndex)) {
      LOGF_E("SSH", "Channel %d: Recovery failed, closing channel",
             channelIndex);
      closeChannel(channelIndex);
      return;
    } else {
      if (now - ch.lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
        LOGF_I("SSH", "Channel %d: Recovery successful, continuing",
               channelIndex);
        ch.lastHealthWarnMs = now;
      }
    }
  }

  // PROTECTION: Avoid excessive mutex contention
  static std::vector<unsigned long> lastProcessTime;
  int maxTrackedChannels = config->getConnectionConfig().maxChannels;
  int neededSize = std::max(maxTrackedChannels, channelIndex + 1);
  if ((int)lastProcessTime.size() < neededSize) {
    lastProcessTime.assign(neededSize, 0);
  }
  if (channelIndex < (int)lastProcessTime.size() &&
      (now - lastProcessTime[channelIndex]) < 5) {
    return; // Skip if processed too recently
  }
  if (channelIndex < (int)lastProcessTime.size()) {
    lastProcessTime[channelIndex] = now;
  }

  // First process pending buffered data to avoid accumulation
  processPendingData(channelIndex);

  // SSH -> Local (read from SSH channel and write to local socket)
  bool readSuccess = processChannelRead(channelIndex);

  // Local -> SSH (read from local socket and write to SSH channel)
  bool writeSuccess = processChannelWrite(channelIndex);

  //   Detect large transfers based on activity
  if (readSuccess || writeSuccess) {
    detectLargeTransfer(channelIndex);
  }

  // Update activity & reset errors on successful traffic
  if (readSuccess || writeSuccess) {
    ch.lastActivity = now;
    ch.consecutiveErrors = 0;    // Reset errors after success
    ch.healthUnhealthyCount = 0; // Healthy traffic observed
  }

  // Check if channel should be gracefully closed
  if (ch.gracefulClosing) {
    // Force processing of pending data before closing
    processPendingData(channelIndex);

    // Check if unified buffers are fully drained
    bool allEmpty =
        (ch.sshToLocalBuffer ? ch.sshToLocalBuffer->empty() : true) &&
        (ch.localToSshBuffer ? ch.localToSshBuffer->empty() : true);

    if (allEmpty) {
      LOGF_I("SSH", "Channel %d: Graceful close completed - all buffers empty",
             channelIndex);
      closeChannel(channelIndex);
    } else {
      // Log unified buffer state for diagnostics
      LOGF_D("SSH",
             "Channel %d: Graceful close waiting - buffers: ssh2local=%zu, "
             "local2ssh=%zu",
             channelIndex,
             ch.sshToLocalBuffer ? ch.sshToLocalBuffer->size() : 0,
             ch.localToSshBuffer ? ch.localToSshBuffer->size() : 0);
    }
  }
}

void SSHTunnel::closeChannel(int channelIndex, ChannelCloseReason reason) {
  if (!channels || channelIndex < 0 ||
      channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }

  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active)
    return;

  unsigned long sessionDuration = millis() - ch.lastActivity;

  LOGF_I("SSH",
         "Closing channel %d (session: %lums, rx: %d bytes, tx: %d bytes, "
         "errors: %d)",
         channelIndex, sessionDuration, ch.totalBytesReceived,
         ch.totalBytesSent, ch.consecutiveErrors);

  flushPendingData(channelIndex);

  if (ch.channel) {
    if (lockSession(pdMS_TO_TICKS(500))) {
      libssh2_channel_close(ch.channel);
      libssh2_channel_free(ch.channel);
      unlockSession();
    }
    ch.channel = nullptr;
  }

  if (ch.localSocket >= 0) {
    int socketToClose = ch.localSocket;
    ch.localSocket = -1;

    shutdown(socketToClose, SHUT_RDWR);
    vTaskDelay(pdMS_TO_TICKS(10));
    close(socketToClose);

    LOGF_D("SSH", "Channel %d: Local socket %d closed safely", channelIndex,
           socketToClose);
  }

  if (ch.largeTransferInProgress) {
    ch.largeTransferInProgress = false;
    emitLargeTransferEvent(channelIndex, false);
  }

  ch.active = false;
  ch.lastActivity = 0;
  ch.pendingBytes = 0;
  ch.flowControlPaused = false;
  ch.localReadPaused = false;
  ch.totalBytesReceived = 0;
  ch.totalBytesSent = 0;
  ch.lastSuccessfulWrite = 0;
  ch.lastSuccessfulRead = 0;
  ch.priority = config->getConnectionConfig().defaultChannelPriority;
  ch.effectivePriority = ch.priority;
  ch.gracefulClosing = false;
  ch.consecutiveErrors = 0;
  ch.transferStartTime = 0;
  ch.transferredBytes = 0;
  ch.peakBytesPerSecond = 0;
  ch.eagainErrors = 0;
  ch.healthUnhealthyCount = 0;
  ch.lastHardRecoveryMs = 0;
  ch.lastHealthWarnMs = 0;
  ch.socketRecvErrors = 0;
  ch.fatalCryptoErrors = 0;
  ch.lastWriteErrorMs = 0;
  ch.lastErrorDetailLogMs = 0;
  ch.stuckProbeCount = 0;
  ch.socketRecvBurstCount = 0;
  ch.firstSocketRecvErrorMs = 0;
  ch.terminalSocketFailure = false;
  ch.readProbeFailCount = 0;
  ch.writeProbeFailCount = 0;
  ch.localReadTerminated = false;
  ch.lostWriteChunks = 0;
  ch.queuedBytesToLocal = 0;
  ch.queuedBytesToRemote = 0;
  ch.remoteEof = false;

  if (ch.sshToLocalBuffer) {
    ch.sshToLocalBuffer->clear();
  }
  if (ch.localToSshBuffer) {
    ch.localToSshBuffer->clear();
  }

  SAFE_FREE(ch.deferredToLocal);
  ch.deferredToLocal = nullptr;
  ch.deferredToLocalSize = 0;
  ch.deferredToLocalOffset = 0;
  SAFE_FREE(ch.deferredToRemote);
  ch.deferredToRemote = nullptr;
  ch.deferredToRemoteSize = 0;
  ch.deferredToRemoteOffset = 0;

  memset(&ch.endpoint, 0, sizeof(ch.endpoint));
  emitChannelClosed(channelIndex, reason);
}

void SSHTunnel::cleanupInactiveChannels() {
  unsigned long now = millis();
  int maxChannels = config->getConnectionConfig().maxChannels;
  int channelTimeout = config->getConnectionConfig().channelTimeoutMs;
  int activeBefore = getActiveChannels();
  static std::vector<unsigned long> lastGracefulLog;
  static std::vector<unsigned long> lastThrottleSkipLog;
  int neededSize = maxChannels;
  if ((int)lastGracefulLog.size() < neededSize) {
    lastGracefulLog.assign(neededSize, 0);
  }
  if ((int)lastThrottleSkipLog.size() < neededSize) {
    lastThrottleSkipLog.assign(neededSize, 0);
  }

  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active) {
      unsigned long timeSinceActivity = now - channels[i].lastActivity;
      bool pendingWork = channelHasPendingWork(channels[i]);

      //   Detect & repair with hysteresis/cooldown to avoid noisy recoveries
      if (!isChannelHealthy(i)) {
        channels[i].healthUnhealthyCount++;
        if (channels[i].healthUnhealthyCount < HEALTH_UNHEALTHY_THRESHOLD) {
          if (now - channels[i].lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
            LOGF_D("SSH", "Channel %d unhealthy (%d) -> graceful recover", i,
                   channels[i].healthUnhealthyCount);
            channels[i].lastHealthWarnMs = now;
          }
          gracefulRecoverChannel(i);
        } else if (now - channels[i].lastHardRecoveryMs >
                   RECOVERY_COOLDOWN_MS) {
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
        if ((channels[i].sshToLocalBuffer
                 ? channels[i].sshToLocalBuffer->empty()
                 : true) &&
            (channels[i].localToSshBuffer
                 ? channels[i].localToSshBuffer->empty()
                 : true)) {
          shouldClose = true;
          LOGF_I("SSH", "Channel %d graceful close completed", i);
        } else if (timeSinceActivity >
                   60000) { // 60 seconds instead of 30 for graceful close
          shouldClose = true;
          LOGF_W("SSH",
                 "Channel %d graceful close timeout - forcing close with "
                 "pending data",
                 i);
          LOGF_W("SSH", "Channel %d buffers: ssh2local=%zu, local2ssh=%zu", i,
                 channels[i].sshToLocalBuffer
                     ? channels[i].sshToLocalBuffer->size()
                     : 0,
                 channels[i].localToSshBuffer
                     ? channels[i].localToSshBuffer->size()
                     : 0);
        } else {
          // Periodic log of state during graceful close
          if (i < (int)lastGracefulLog.size() &&
              (now - lastGracefulLog[i] > 5000)) { // Log every 5s
            LOGF_I("SSH",
                   "Channel %d graceful close in progress - buffers: "
                   "ssh2local=%zu, local2ssh=%zu",
                   i,
                   channels[i].sshToLocalBuffer
                       ? channels[i].sshToLocalBuffer->size()
                       : 0,
                   channels[i].localToSshBuffer
                       ? channels[i].localToSshBuffer->size()
                       : 0);
            lastGracefulLog[i] = now;
          }
        }
      } else {
        // Normal timeout but more tolerant
        if (pendingWork && globalRateLimitBytesPerSec > 0 &&
            globalThrottleActive) {
          channels[i].lastActivity = now;
          if (i < (int)lastThrottleSkipLog.size() &&
              (now - lastThrottleSkipLog[i] > 2000)) {
            lastThrottleSkipLog[i] = now;
            LOGF_D("SSH",
                   "Channel %d: Timeout skipped (global throttle, queued=%zu)",
                   i, channels[i].queuedBytesToRemote);
          }
          continue;
        }
        if (timeSinceActivity >
            channelTimeout * 2) { // Double du timeout normal
          shouldClose = true;
          LOGF_W("SSH", "Channel %d timeout after %lums, closing", i,
                 timeSinceActivity);
        }
        // Channels with too many consecutive errors
        else if (channels[i].consecutiveErrors > 10) {
          shouldClose = true;
          LOGF_W("SSH", "Channel %d has too many errors (%d), closing", i,
                 channels[i].consecutiveErrors);
        }
        // Unified buffers too full for too long
        else if (((channels[i].sshToLocalBuffer
                       ? channels[i].sshToLocalBuffer->size()
                       : 0) > 8192 ||
                  (channels[i].localToSshBuffer
                       ? channels[i].localToSshBuffer->size()
                       : 0) > 8192) &&
                 timeSinceActivity > 60000) {
          shouldClose = true;
          LOGF_W("SSH", "Channel %d has full buffers for %lums, closing", i,
                 timeSinceActivity);
        }
        // Stale data in unified buffers (>10 seconds)
        else if (!(channels[i].sshToLocalBuffer
                       ? channels[i].sshToLocalBuffer->empty()
                       : true) ||
                 !(channels[i].localToSshBuffer
                       ? channels[i].localToSshBuffer->empty()
                       : true)) {
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
        totalQueued +=
            (channels[i].sshToLocalBuffer ? channels[i].sshToLocalBuffer->size()
                                          : 0) +
            (channels[i].localToSshBuffer ? channels[i].localToSshBuffer->size()
                                          : 0);
      }
    }
    LOGF_I(
        "SSH",
        "Channel status: %d active, %d total queued bytes, Dropped=%lu bytes",
        activeAfter, totalQueued, droppedBytes);
    lastLog = now;
  }
}

void SSHTunnel::printChannelStatistics() {
  static unsigned long lastStatsTime = 0;
  unsigned long now = millis();

  // Print stats every 2 minutes
  if (now - lastStatsTime < 120000)
    return;
  lastStatsTime = now;

  int activeCount = 0;
  int flowPausedCount = 0;
  int pendingBytesTotal = 0;
  int basePriorityHigh = 0;
  int basePriorityNormal = 0;
  int basePriorityLow = 0;
  int effectiveHigh = 0;
  int effectiveNormal = 0;
  int effectiveLow = 0;

  int maxChannels = config->getConnectionConfig().maxChannels;
  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active) {
      activeCount++;
      if (channels[i].flowControlPaused)
        flowPausedCount++;
      pendingBytesTotal += channels[i].pendingBytes;

      switch (channels[i].priority) {
      case 2:
        basePriorityHigh++;
        break;
      case 1:
        basePriorityNormal++;
        break;
      default:
        basePriorityLow++;
        break;
      }

      switch (channels[i].effectivePriority) {
      case 2:
        effectiveHigh++;
        break;
      case 1:
        effectiveNormal++;
        break;
      default:
        effectiveLow++;
        break;
      }
    }
  }

  LOGF_I("SSH",
         "Channel Stats: Active=%d/%d, FlowPaused=%d, TotalPending=%d bytes, "
         "Dropped=%lu bytes",
         activeCount, maxChannels, flowPausedCount, pendingBytesTotal,
         droppedBytes);
  LOGF_I("SSH",
         "Channel Priority: Base H/M/L=%d/%d/%d, Effective H/M/L=%d/%d/%d",
         basePriorityHigh, basePriorityNormal, basePriorityLow, effectiveHigh,
         effectiveNormal, effectiveLow);

  // Special alerts
  if (activeCount == maxChannels) {
    LOGF_W("SSH", "WARNING: All channels in use - potential bottleneck");
  }
  if (flowPausedCount > activeCount / 2) {
    LOGF_W("SSH",
           "WARNING: Many channels flow-paused (%d/%d) - network congestion",
           flowPausedCount, activeCount);
  }
}

void SSHTunnel::sendKeepAlive() {
  if (!session)
    return;

  int seconds = 0;
  int rc = LIBSSH2_ERROR_EAGAIN;
  if (lockSession(pdMS_TO_TICKS(200))) {
    rc = libssh2_keepalive_send(session, &seconds);
    unlockSession();
  } else {
    LOG_W("SSH", "Keep-alive skipped (session lock timeout)");
    return;
  }
  if (rc == 0) {
    keepAliveSocketSendFailures = 0;
    LOGF_D("SSH", "Keep-alive sent, next in %d seconds", seconds);
  } else if (rc == LIBSSH2_ERROR_SOCKET_SEND) {
    keepAliveSocketSendFailures++;
    LOGF_W("SSH", "Keep-alive failed: %d (%d/3)", rc,
           keepAliveSocketSendFailures);
    if (keepAliveSocketSendFailures >= 3) {
      LOG_W("SSH",
            "Keep-alive socket send failed 3 times, scheduling reconnection");
      keepAliveSocketSendFailures = 0;
      state = TUNNEL_ERROR;
    }
  } else if (rc != LIBSSH2_ERROR_EAGAIN) {
    keepAliveSocketSendFailures = 0;
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
    LOGF_W("SSH", "checkConnection: retval=%d so_error=%d (%s)", retval, error,
           strerror(error));
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

int SSHTunnel::getBoundPort() const { return boundPort; }

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

void SSHTunnel::setEventHandlers(const SSHTunnelEvents &handlers) {
  eventHandlers = handlers;
}

bool SSHTunnel::addReverseTunnel(const TunnelConfig &mapping) {
  config->addTunnelMapping(mapping);

  if (state != TUNNEL_CONNECTED) {
    return true;
  }

  if ((int)listeners.size() >=
      config->getConnectionConfig().maxReverseListeners) {
    LOG_W("SSH", "Cannot add reverse tunnel: listener limit reached");
    emitErrorEvent(-4, "Reverse listener limit reached");
    return false;
  }

  ListenerEntry entry;
  entry.mapping = mapping;
  if (!createListenerForMapping(mapping, entry)) {
    return false;
  }

  listeners.push_back(entry);
  if (boundPort < 0) {
    boundPort = entry.boundPort;
  }

  LOGF_I("SSH", "Dynamic reverse listener added: %s:%d (bound %d) -> %s:%d",
         mapping.remoteBindHost.c_str(), mapping.remoteBindPort,
         entry.boundPort, mapping.localHost.c_str(), mapping.localPort);
  return true;
}

bool SSHTunnel::removeReverseTunnel(const String &remoteHost, int remotePort) {
  const std::vector<TunnelConfig> &mappings = config->getTunnelMappings();
  size_t mappingIndex = mappings.size();
  for (size_t i = 0; i < mappings.size(); ++i) {
    if (mappings[i].remoteBindHost == remoteHost &&
        mappings[i].remoteBindPort == remotePort) {
      mappingIndex = i;
      break;
    }
  }

  if (mappingIndex < mappings.size()) {
    config->removeTunnelMapping(mappingIndex);
  }

  bool removed = false;
  for (auto it = listeners.begin(); it != listeners.end(); ++it) {
    if (it->mapping.remoteBindHost == remoteHost &&
        it->mapping.remoteBindPort == remotePort) {
      cancelListener(*it);
      listeners.erase(it);
      removed = true;
      break;
    }
  }

  if (removed) {
    boundPort = listeners.empty() ? -1 : listeners.front().boundPort;
    LOGF_I("SSH", "Reverse listener removed: %s:%d", remoteHost.c_str(),
           remotePort);
  } else {
    LOGF_W("SSH", "Reverse listener not found for %s:%d", remoteHost.c_str(),
           remotePort);
  }

  return removed;
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

bool SSHTunnel::lockSession(TickType_t ticks) {
  if (sessionMutex == NULL) {
    return false;
  }
  TickType_t waitTicks = ticks;
  if (waitTicks == 0) {
    waitTicks = 1; // ensure we at least yield once when timeout 0 requested
  }
  return xSemaphoreTake(sessionMutex, waitTicks) == pdTRUE;
}

void SSHTunnel::unlockSession() {
  if (sessionMutex != NULL) {
    xSemaphoreGive(sessionMutex);
  }
}

bool SSHTunnel::lockThrottle(TickType_t ticks) {
  if (throttleMutex == NULL) {
    return false;
  }
  TickType_t waitTicks = ticks;
  if (waitTicks == 0) {
    waitTicks = 1;
  }
  return xSemaphoreTake(throttleMutex, waitTicks) == pdTRUE;
}

void SSHTunnel::unlockThrottle() {
  if (throttleMutex != NULL) {
    xSemaphoreGive(throttleMutex);
  }
}

// New methods with separate mutexes and short timeout
bool SSHTunnel::lockChannelRead(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 ||
      channelIndex >= config->getConnectionConfig().maxChannels) {
    return false;
  }

  if (channels[channelIndex].readMutex == NULL) {
    return false;
  }

  // MONITORING: Track locking attempts
  unsigned long start = millis();

  // Timeout restored to stable v1.3 value (100ms)
  BaseType_t result =
      xSemaphoreTake(channels[channelIndex].readMutex, pdMS_TO_TICKS(100));
  unsigned long duration = millis() - start;

  if (result != pdTRUE) {
    // Don't log as WARNING to avoid spam - just count
    channels[channelIndex].readMutexFailures++;
    if (channels[channelIndex].readMutexFailures % 50 ==
        1) { // Log only every 50 times
      LOGF_D("SSH", "Channel %d: Read mutex timeout after %lums (failures=%d)",
             channelIndex, duration, channels[channelIndex].readMutexFailures);
    }
    return false;
  }

  if (duration >
      40) { // Threshold reduced 50 -> 40ms and DEBUG log (cache flush)
    LOGF_D("SSH", "Channel %d: READ mutex acquired after %lums (slow)",
           channelIndex, duration);
  }

  return true;
}

void SSHTunnel::unlockChannelRead(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 ||
      channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }

  if (channels[channelIndex].readMutex != NULL) {
    // Defensive: try to give; if it fails in future, convert to counting log
    xSemaphoreGive(channels[channelIndex].readMutex);
  }
}

bool SSHTunnel::lockChannelWrite(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 ||
      channelIndex >= config->getConnectionConfig().maxChannels) {
    return false;
  }

  if (channels[channelIndex].writeMutex == NULL) {
    return false;
  }

  // MONITORING: Track locking attempts
  unsigned long start = millis();

  // Timeout restored to stable v1.3 value (100ms)
  BaseType_t result =
      xSemaphoreTake(channels[channelIndex].writeMutex, pdMS_TO_TICKS(100));
  unsigned long duration = millis() - start;

  if (result != pdTRUE) {
    // Don't log as WARNING to avoid spam - just count
    channels[channelIndex].writeMutexFailures++;
    if (channels[channelIndex].writeMutexFailures % 50 ==
        1) { // Log only every 50 times
      LOGF_D("SSH", "Channel %d: Write mutex timeout after %lums (failures=%d)",
             channelIndex, duration, channels[channelIndex].writeMutexFailures);
    }
    return false;
  }

  if (duration > 40) { // Threshold reduced 50 -> 40ms and DEBUG log
    LOGF_D("SSH", "Channel %d: WRITE mutex acquired after %lums (slow)",
           channelIndex, duration);
  }

  return true;
}

void SSHTunnel::unlockChannelWrite(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 ||
      channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }

  if (channels[channelIndex].writeMutex != NULL) {
    xSemaphoreGive(channels[channelIndex].writeMutex);
  }
}

// Compatibility methods (deprecated) - use writeMutex by default
bool SSHTunnel::lockChannel(int channelIndex) {
  return lockChannelWrite(channelIndex);
}

void SSHTunnel::unlockChannel(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 ||
      channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }

  if (channels[channelIndex].writeMutex != NULL) {
    xSemaphoreGive(channels[channelIndex].writeMutex);
  }
}

// FIXED: Safe method to handle mutex issues without destroying them
void SSHTunnel::safeRetryMutexAccess(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 ||
      channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }

  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active)
    return; // Ignore inactive slots
  if (ch.gracefulClosing)
    return; // Already closing, no probe

  bool readOk = true;
  bool writeOk = true;

  // Non-blocking probe (0 tick) to avoid priority inheritance complications
  if (ch.readMutex) {
    if (xSemaphoreTake(ch.readMutex, 0) == pdTRUE) {
      xSemaphoreGive(ch.readMutex);
    } else {
      readOk = false;
    }
  }
  if (ch.writeMutex) {
    if (xSemaphoreTake(ch.writeMutex, 0) == pdTRUE) {
      xSemaphoreGive(ch.writeMutex);
    } else {
      writeOk = false;
    }
  }

  if (!readOk || !writeOk) {
    unsigned long now = millis();
    // Throttle WARN to every 5000 ms, DEBUG otherwise
    if (now - ch.lastHealthWarnMs > 5000) {
      ch.lastHealthWarnMs = now;
      LOGF_W("SSH", "Channel %d: Mutex probe stuck (read=%s, write=%s)",
             channelIndex, readOk ? "OK" : "STUCK", writeOk ? "OK" : "STUCK");
    } else {
      LOGF_D("SSH", "Channel %d: Mutex probe (read=%s, write=%s)", channelIndex,
             readOk ? "OK" : "STUCK", writeOk ? "OK" : "STUCK");
    }
    // Escalate with dedicated counter (does NOT touch consecutiveErrors)
    ch.stuckProbeCount++;
    if (ch.stuckProbeCount >= STUCK_PROBE_THRESHOLD) {
      LOGF_W(
          "SSH",
          "Channel %d: Stuck mutex threshold reached (%d) -> graceful closing",
          channelIndex, ch.stuckProbeCount);
      ch.gracefulClosing = true;
    }
  } else {
    // Reset probe counter on success
    if (ch.stuckProbeCount)
      ch.stuckProbeCount = 0;
  }
}

// New methods to improve transmission reliability

void SSHTunnel::cleanupPartialInit(int maxChannels) {
  if (channels != nullptr) {
    for (int i = 0; i < maxChannels; ++i) {
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
    channels = nullptr;
  }

  SAFE_FREE(rxBuffer);
  SAFE_FREE(txBuffer);

  if (libssh2Initialized) {
    libssh2_exit();
    libssh2Initialized = false;
  }
}

size_t SSHTunnel::getConfiguredRingBufferSize() const {
  if (ringBufferCapacity > 0) {
    return ringBufferCapacity;
  }

  size_t configured = config->getConnectionConfig().tunnelRingBufferSize;
  if (configured == 0) {
    configured = 32 * 1024;
  }
  return configured;
}

size_t SSHTunnel::getHighWaterLocal() const {
  if (ringBufferCapacity > 0) {
    return (ringBufferCapacity * 3) / 4;
  }
  return DEFAULT_HIGH_WATER_LOCAL;
}

size_t SSHTunnel::getLowWaterLocal() const {
  size_t high = getHighWaterLocal();
  if (high == 0) {
    return DEFAULT_LOW_WATER_LOCAL;
  }
  return high / 2;
}

size_t SSHTunnel::getPendingToRemoteBytes(const TunnelChannel &ch) const {
  size_t deferred = 0;
  if (ch.deferredToRemote &&
      ch.deferredToRemoteOffset < ch.deferredToRemoteSize) {
    deferred = ch.deferredToRemoteSize - ch.deferredToRemoteOffset;
  }
  return ch.queuedBytesToRemote + deferred;
}

uint16_t SSHTunnel::getDataTaskStackSize() const {
  uint16_t configured = config->getConnectionConfig().dataTaskStackSize;
  if (configured == 0) {
    configured = 4096;
  }
  return configured;
}

int8_t SSHTunnel::getDataTaskCoreAffinity() const {
  return config->getConnectionConfig().dataTaskCoreAffinity;
}

bool SSHTunnel::processChannelRead(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active || !ch.channel || ch.localSocket < 0) {
    return false;
  }

  // Before new read, try to enqueue deferred SSH->Local residual data first
  if (ch.deferredToLocal && ch.deferredToLocalOffset < ch.deferredToLocalSize) {
    size_t remain = ch.deferredToLocalSize - ch.deferredToLocalOffset;
    size_t q =
        queueData(channelIndex, ch.deferredToLocal + ch.deferredToLocalOffset,
                  remain, true);
    ch.deferredToLocalOffset += q;
    if (ch.deferredToLocalOffset >= ch.deferredToLocalSize) {
      SAFE_FREE(ch.deferredToLocal);
      ch.deferredToLocal = nullptr;
      ch.deferredToLocalSize = ch.deferredToLocalOffset = 0;
    }
  }

  if (!lockChannelRead(channelIndex)) {
    return false;
  }

  bool success = false;
  size_t bufferSize = getConfiguredRingBufferSize();
  unsigned long now = millis();
  bool remoteEofDetected = false;
  const size_t highWaterLocal = getHighWaterLocal();
  const size_t lowWaterLocal = getLowWaterLocal();

  //   Flow control with optimized high/low watermarks for ESP32
  if (ch.flowControlPaused) {
    // Check whether we can resume
    if (ch.queuedBytesToLocal < lowWaterLocal) {
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

  if (ch.queuedBytesToLocal > highWaterLocal) {
    ch.flowControlPaused = true;
    LOGF_W("SSH", "Channel %d: Flow control PAUSE (queuedToLocal=%zu)",
           channelIndex, ch.queuedBytesToLocal);
    unlockChannelRead(channelIndex);
    return false;
  }

  // Double check after acquiring the read mutex
  if (ch.active && ch.channel && ch.localSocket >= 0) {
    // Check socket state before write
    int sockError = 0;
    socklen_t errLen = sizeof(sockError);
    if (getsockopt(ch.localSocket, SOL_SOCKET, SO_ERROR, &sockError, &errLen) ==
            0 &&
        sockError != 0) {
      LOGF_I(
          "SSH",
          "Channel %d: Socket error before write: %s (queuedL=%zu queuedR=%zu)",
          channelIndex, strerror(sockError), ch.queuedBytesToLocal,
          ch.queuedBytesToRemote);
      ch.gracefulClosing = true;
      unlockChannelRead(channelIndex);
      return false;
    }

    ssize_t bytesRead = 0;
    bool channelEof = false;
    String readErrorDetail = "";
    if (lockSession(pdMS_TO_TICKS(200))) {
      bytesRead =
          libssh2_channel_read(ch.channel, (char *)rxBuffer, bufferSize);
      if (bytesRead == 0) {
        channelEof = libssh2_channel_eof(ch.channel);
      } else if (bytesRead < 0 && bytesRead != LIBSSH2_ERROR_EAGAIN) {
        char *errmsg = nullptr;
        int errlen = 0;
        libssh2_session_last_error(session, &errmsg, &errlen, 0);
        if (errmsg && errlen > 0) {
          readErrorDetail = String(errmsg).substring(0, errlen);
        }
      }
      unlockSession();
    } else {
      unlockChannelRead(channelIndex);
      return false;
    }

    if (bytesRead > 0) {
      ch.lastSuccessfulRead = now;
      // Reset burst counters on successful read
      if (ch.socketRecvBurstCount) {
        ch.socketRecvBurstCount = 0;
        ch.firstSocketRecvErrorMs = 0;
      }
      // DIAGNOSTIC: Check data consistency for large transfers
      if (ch.largeTransferInProgress && bytesRead > 1024) {
        // Simple check - count non-null bytes to detect corruption
        size_t nonNullBytes = 0;
        for (size_t i = 0; i < bytesRead; i++) {
          if (rxBuffer[i] != 0)
            nonNullBytes++;
        }

        // If more than 90% are zeros, it's suspicious
        if (nonNullBytes < (bytesRead * 0.1)) {
          LOGF_W(
              "SSH",
              "Channel %d: Suspicious data pattern detected (%zu/%zd non-null)",
              channelIndex, nonNullBytes, bytesRead);
        }
      }

      // Try direct write to the local socket first
      ssize_t written = send(ch.localSocket, rxBuffer, bytesRead, MSG_DONTWAIT);

      if (written == bytesRead) {
        // Full success
        ch.totalBytesReceived += written;
        ch.lastSuccessfulWrite = now;
        if (lockStats()) {
          bytesReceived += written;
          unlockStats();
        }
        ch.lastActivity = millis();
        success = true;

        // DIAGNOSTIC: Log to track large transfers and detect issues
        if (written > 4096) { // > 4KB chunks
          LOGF_I("SSH",
                 "Channel %d: SSH->Local LARGE chunk %zd bytes (total RX: %zu)",
                 channelIndex, written, ch.totalBytesReceived);
        } else if (ch.largeTransferInProgress) {
          LOGF_D("SSH",
                 "Channel %d: SSH->Local %zd bytes during large transfer "
                 "(total: %zu)",
                 channelIndex, written, ch.totalBytesReceived);
        } else {
          LOGF_D("SSH", "Channel %d: SSH->Local %zd bytes (direct)",
                 channelIndex, written);
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
          // Store leftover not queued into a deferred buffer
          size_t leftover = remaining - q;
          size_t unqueuedOffset = written + q; // position dans rxBuffer
          if (leftover > 0) {
            // Merge with existing deferred residual if present
            size_t existing = 0;
            size_t existingRemain = 0;
            if (ch.deferredToLocal) {
              existingRemain =
                  ch.deferredToLocalSize - ch.deferredToLocalOffset;
              existing = existingRemain;
            }
            uint8_t *newBuf =
                (uint8_t *)safeMalloc(existing + leftover, "DEFER_LOC_RX");
            if (newBuf) {
              size_t pos = 0;
              if (existingRemain > 0) {
                memcpy(newBuf, ch.deferredToLocal + ch.deferredToLocalOffset,
                       existingRemain);
                pos += existingRemain;
              }
              memcpy(newBuf + pos, rxBuffer + unqueuedOffset, leftover);
              SAFE_FREE(ch.deferredToLocal);
              ch.deferredToLocal = newBuf;
              ch.deferredToLocalSize = existingRemain + leftover;
              ch.deferredToLocalOffset = 0; // restart from beginning
              LOGF_W("SSH", "Channel %d: Deferred %zu bytes (SSH->Local)",
                     channelIndex, leftover);
            } else {
              LOGF_E("SSH",
                     "Channel %d: Allocation failed for deferred SSH->Local "
                     "(%zu bytes dropped)",
                     channelIndex, leftover);
              char dropMsg[128];
              snprintf(dropMsg, sizeof(dropMsg),
                       "alloc failed deferring %zu bytes (ssh->local)",
                       leftover);
              emitChannelError(channelIndex, TunnelErrorCode::DropSshToLocal,
                               ENOMEM, dropMsg);
              ch.lostWriteChunks++; // comptage diagnostique
              ch.bytesDropped += leftover;
              if (lockStats()) {
                droppedBytes += leftover;
                unlockStats();
              }
            }
          }
        }
        success = true; // Consider success (no loss of already written bytes)
        ch.lastActivity = millis();
      } else if (written < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // Socket full - queue all data
          size_t q = queueData(channelIndex, rxBuffer, bytesRead, true);
          if (q < (size_t)bytesRead) {
            size_t leftover = (size_t)bytesRead - q;
            uint8_t *newBuf =
                (uint8_t *)safeMalloc(leftover, "DEFER_LOC_RX_FULL");
            if (newBuf) {
              memcpy(newBuf, rxBuffer + q, leftover);
              if (ch.deferredToLocal) {
                SAFE_FREE(ch.deferredToLocal);
              }
              ch.deferredToLocal = newBuf;
              ch.deferredToLocalSize = leftover;
              ch.deferredToLocalOffset = 0;
              LOGF_W("SSH", "Channel %d: Deferred %zu bytes (socket full)",
                     channelIndex, leftover);
            } else {
              LOGF_E("SSH",
                     "Channel %d: Allocation failed deferring %zu bytes (drop)",
                     channelIndex, leftover);
              char dropMsg[128];
              snprintf(dropMsg, sizeof(dropMsg),
                       "alloc failed deferring %zu bytes (local->ssh)",
                       leftover);
              emitChannelError(channelIndex, TunnelErrorCode::DropSshToLocal,
                               ENOMEM, dropMsg);
              ch.lostWriteChunks++;
              ch.bytesDropped += leftover;
              if (lockStats()) {
                droppedBytes += leftover;
                unlockStats();
              }
            }
          }
          success = true;
          ch.lastActivity = millis();
        } else if (errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN ||
                   errno == ESHUTDOWN || errno == ETIMEDOUT) {
          LOGF_I("SSH",
                 "Channel %d: Local connection closed during write (%s), "
                 "initiating graceful close",
                 channelIndex, strerror(errno));
          ch.gracefulClosing = true;
          success = true; // Treat as normal close
        } else {
          LOGF_W("SSH", "Channel %d: Local write error: %s (errno=%d)",
                 channelIndex, strerror(errno), errno);
          ch.consecutiveErrors++;
          char errMsg[128];
          snprintf(errMsg, sizeof(errMsg), "local write err=%d %s", errno,
                   strerror(errno));
          emitChannelError(channelIndex, TunnelErrorCode::LocalSocketError,
                           errno, errMsg);
        }
      }
    } else if (bytesRead == 0) {
      // 0 -> explicitly check EOF
      if (channelEof) {
        bool firstEof = !ch.remoteEof;
        if (firstEof) {
          LOGF_I("SSH", "Channel %d: SSH channel EOF (queuedL=%zu queuedR=%zu)",
                 channelIndex, ch.queuedBytesToLocal, ch.queuedBytesToRemote);
        } else {
          LOGF_D("SSH", "Channel %d: SSH channel EOF (repeat)", channelIndex);
        }
        ch.remoteEof = true;
        ch.gracefulClosing = true;
        remoteEofDetected = true;
        if (firstEof && ch.localSocket >= 0) {
          shutdown(ch.localSocket, SHUT_WR);
          LOGF_D("SSH", "Channel %d: Local shutdown(SHUT_WR) after remote EOF",
                 channelIndex);
        }
      }
    } else if (bytesRead < 0 && bytesRead != LIBSSH2_ERROR_EAGAIN) {
      if (bytesRead == LIBSSH2_ERROR_SOCKET_RECV) {
        unsigned long nowErr = millis();
        ch.socketRecvErrors++;
        if (ch.socketRecvBurstCount == 0)
          ch.firstSocketRecvErrorMs = nowErr;
        ch.socketRecvBurstCount++;
        if (!ch.terminalSocketFailure &&
            ch.socketRecvBurstCount >= SOCKET_RECV_BURST_THRESHOLD &&
            (nowErr - ch.firstSocketRecvErrorMs) <=
                SOCKET_RECV_BURST_WINDOW_MS) {
          ch.terminalSocketFailure = true;
          ch.gracefulClosing = true;
          LOGF_W("SSH",
                 "Channel %d: Terminal -43 burst (read) count=%d window=%lums "
                 "queuedL=%zu queuedR=%zu",
                 channelIndex, ch.socketRecvBurstCount,
                 (nowErr - ch.firstSocketRecvErrorMs), ch.queuedBytesToLocal,
                 ch.queuedBytesToRemote);
          emitChannelError(channelIndex, TunnelErrorCode::SshSocketRecv,
                           (int)bytesRead, "terminal -43 recv burst (read)");
          recordTerminalSocketFailure(nowErr);
        } else if (!ch.terminalSocketFailure) {
          if ((nowErr - ch.lastErrorDetailLogMs) > 2000) {
            ch.lastErrorDetailLogMs = nowErr;
            const char *detail = readErrorDetail.length()
                                     ? readErrorDetail.c_str()
                                     : "socket_recv";
            LOGF_W("SSH",
                   "Channel %d: -43 recv (read) burst=%d queuedR=%zu detail=%s",
                   channelIndex, ch.socketRecvBurstCount,
                   ch.queuedBytesToRemote, detail);
            emitChannelError(channelIndex, TunnelErrorCode::SshSocketRecv,
                             (int)bytesRead, "ssh read recv error (-43)");
          }
        }
      } else if (bytesRead == LIBSSH2_ERROR_DECRYPT) {
        ch.fatalCryptoErrors++;
        ch.gracefulClosing = true;
        unsigned long nowErr = millis();
        if (nowErr - ch.lastErrorDetailLogMs > 2000) {
          ch.lastErrorDetailLogMs = nowErr;
          emitChannelError(channelIndex, TunnelErrorCode::SshDecrypt,
                           (int)bytesRead, "ssh decrypt error (read)");
        }
      } else {
        const char *detail =
            readErrorDetail.length() ? readErrorDetail.c_str() : "unknown";
        LOGF_W("SSH", "Channel %d: SSH read error: %d detail=%s", channelIndex,
               (int)bytesRead, detail);
        ch.consecutiveErrors++;
        emitChannelError(channelIndex, mapSshErrorToCode((int)bytesRead, false),
                         (int)bytesRead, "ssh read error");
      }
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

  // Backoff: if we recently had an error and are still accumulating, skip this
  // cycle
  unsigned long nowPre = millis();
  if (ch.consecutiveErrors > 0 && (nowPre - ch.lastWriteErrorMs) < 40) {
    return false;
  }
  const size_t highWaterLocal = getHighWaterLocal();
  const size_t lowWaterLocal = getLowWaterLocal();

  // Before reading local socket, try to re-enqueue Local->SSH deferred
  // residuals first
  if (ch.deferredToRemote &&
      ch.deferredToRemoteOffset < ch.deferredToRemoteSize) {
    size_t remain = ch.deferredToRemoteSize - ch.deferredToRemoteOffset;
    size_t q =
        queueData(channelIndex, ch.deferredToRemote + ch.deferredToRemoteOffset,
                  remain, false);
    ch.deferredToRemoteOffset += q;
    if (ch.deferredToRemoteOffset >= ch.deferredToRemoteSize) {
      SAFE_FREE(ch.deferredToRemote);
      ch.deferredToRemote = nullptr;
      ch.deferredToRemoteSize = ch.deferredToRemoteOffset = 0;
    }
  }

  // Backpressure: pause local reads until backlog drains below LOW watermark
  size_t pendingToRemote = getPendingToRemoteBytes(ch);
  if (ch.localReadPaused) {
    if (pendingToRemote < lowWaterLocal) {
      ch.localReadPaused = false;
      LOGF_D("SSH",
             "Channel %d: Local read resumed (pending=%zu < %zu, qRemote=%zu)",
             channelIndex, pendingToRemote, lowWaterLocal,
             ch.queuedBytesToRemote);
    }
  } else if (pendingToRemote > highWaterLocal) {
    size_t deferred =
        pendingToRemote > ch.queuedBytesToRemote
            ? (pendingToRemote - ch.queuedBytesToRemote)
            : 0;
    ch.localReadPaused = true;
    LOGF_W("SSH",
           "Channel %d: Critical backpressure (pending=%zu, qRemote=%zu, "
           "deferred=%zu) - pausing local read (resume < %zu)",
           channelIndex, pendingToRemote, ch.queuedBytesToRemote, deferred,
           lowWaterLocal);
  }

  if (!lockChannelWrite(channelIndex)) {
    return false;
  }

  bool success = false;
  size_t bufferSize = getOptimalBufferSize(channelIndex);
  unsigned long now = millis();
  bool dropPending = false;
  String dropReason = "";
  int dropCode = 0;
  bool writeBroken = false;
  bool throttledByGlobalLimit = false;
  static std::vector<unsigned long> lastThrottleLog;
  int throttleLogSize = config->getConnectionConfig().maxChannels;
  int minSize = std::max(throttleLogSize, channelIndex + 1);
  if ((int)lastThrottleLog.size() < minSize) {
    lastThrottleLog.assign(minSize, 0);
  }

  if (ch.active && ch.channel && ch.localSocket >= 0) {
    // 1) Loop-drain already queued data (localToSshBuffer)
    size_t totalWritten = 0;
    int passes = 0;
    if (lockSession(pdMS_TO_TICKS(200))) {
      while (passes < SSH_MAX_WRITES_PER_PASS && ch.localToSshBuffer &&
             !ch.localToSshBuffer->empty()) {
        size_t winSize = 0, winUsed = 0;
        (void)winSize;
        (void)winUsed;

        uint8_t temp[SSH_BUFFER_SIZE];
        size_t chunk = ch.localToSshBuffer->read(temp, sizeof(temp));
        if (chunk == 0)
          break;
        if (chunk < MIN_WRITE_SIZE && !ch.localToSshBuffer->empty()) {
          size_t extra =
              ch.localToSshBuffer->read(temp + chunk, MIN_WRITE_SIZE - chunk);
          chunk += extra;
        }
        size_t allowanceDrain = getGlobalAllowance(chunk);
        if (allowanceDrain == 0 && globalRateLimitBytesPerSec != 0) {
          ch.localToSshBuffer->write(temp, chunk);
          throttledByGlobalLimit = true;
          ch.lastActivity = millis();
          if (channelIndex < (int)lastThrottleLog.size() &&
              (now - lastThrottleLog[channelIndex] > 1000)) {
            lastThrottleLog[channelIndex] = now;
            LOGF_D("SSH",
                   "Channel %d: Global limiter delaying drain (queued=%zu)",
                   channelIndex, ch.queuedBytesToRemote);
          }
          break;
        }
        if (allowanceDrain < chunk) {
          ch.localToSshBuffer->write(temp + allowanceDrain,
                                     chunk - allowanceDrain);
          chunk = allowanceDrain;
          ch.lastActivity = millis();
        }

        String drainErrorDetail = "";
        ssize_t w =
            libssh2_channel_write_ex(ch.channel, 0, (char *)temp, chunk);
        if (w > 0) {
          passes++;
          totalWritten += w;
          ch.totalBytesSent += w;
          ch.queuedBytesToRemote = (ch.queuedBytesToRemote > (size_t)w)
                                       ? ch.queuedBytesToRemote - w
                                       : 0;
          ch.lastSuccessfulWrite = now;
          ch.consecutiveErrors = 0;
          if (ch.socketRecvBurstCount) {
            ch.socketRecvBurstCount = 0;
            ch.firstSocketRecvErrorMs = 0;
          }
          ch.lastActivity = millis();
          commitGlobalTokens((size_t)w);
          if ((size_t)w < chunk) {
            ch.localToSshBuffer->write(temp + w, chunk - w);
            ch.lastActivity = millis();
          }
        } else if (w == LIBSSH2_ERROR_EAGAIN) {
          ch.localToSshBuffer->write(temp, chunk);
          ch.lastActivity = millis();
          break;
        } else {
          ch.consecutiveErrors++;
          ch.lastWriteErrorMs = now;
          if (w == LIBSSH2_ERROR_SOCKET_RECV) {
            ch.socketRecvErrors++;
            if (ch.socketRecvBurstCount == 0)
              ch.firstSocketRecvErrorMs = now;
            ch.socketRecvBurstCount++;
            if (!ch.terminalSocketFailure &&
                ch.socketRecvBurstCount >= SOCKET_RECV_BURST_THRESHOLD &&
                (now - ch.firstSocketRecvErrorMs) <=
                    SOCKET_RECV_BURST_WINDOW_MS) {
              ch.terminalSocketFailure = true;
              ch.gracefulClosing = true;
              LOGF_W("SSH",
                     "Channel %d: Terminal -43 burst (drain) count=%d "
                     "window=%lums qRemote=%zu",
                     channelIndex, ch.socketRecvBurstCount,
                     (now - ch.firstSocketRecvErrorMs), ch.queuedBytesToRemote);
              emitChannelError(channelIndex, TunnelErrorCode::SshSocketRecv,
                               (int)w, "terminal -43 recv burst (drain)");
              emitChannelWriteBroken(channelIndex,
                                     TunnelErrorCode::SshSocketRecv, (int)w,
                                     "terminal -43 recv burst (drain)");
              recordTerminalSocketFailure(now);
            } else if (!ch.terminalSocketFailure) {
              if ((now - ch.lastErrorDetailLogMs) > 2000) {
                ch.lastErrorDetailLogMs = now;
                LOGF_W("SSH",
                       "Channel %d: -43 recv (drain) burst=%d qRemote=%zu",
                       channelIndex, ch.socketRecvBurstCount,
                       ch.queuedBytesToRemote);
                emitChannelError(channelIndex, TunnelErrorCode::SshSocketRecv,
                                 (int)w, "ssh drain recv error (-43)");
              }
            }
          } else if (w == LIBSSH2_ERROR_DECRYPT) {
            ch.fatalCryptoErrors++;
            ch.gracefulClosing = true;
          }
          char *errmsg = nullptr;
          int errlen = 0;
          libssh2_session_last_error(session, &errmsg, &errlen, 0);
          if (errmsg && errlen > 0) {
            drainErrorDetail = String(errmsg).substring(0, errlen);
          }
          if (now - ch.lastErrorDetailLogMs > 2000) {
            ch.lastErrorDetailLogMs = now;
            const char *detail = drainErrorDetail.length()
                                     ? drainErrorDetail.c_str()
                                     : "unknown";
            LOGF_W("SSH",
                   "Channel %d: Write error %zd during drain cons=%d "
                   "sockRecv=%d crypt=%d qRemote=%zu detail=%s",
                   channelIndex, w, ch.consecutiveErrors, ch.socketRecvErrors,
                   ch.fatalCryptoErrors, ch.queuedBytesToRemote, detail);
            char errMsg[128];
            snprintf(errMsg, sizeof(errMsg),
                     "ssh drain write err=%zd detail=%s", w, detail);
            emitChannelError(channelIndex, mapSshErrorToCode((int)w, true),
                             (int)w, errMsg);
          }
          ch.localToSshBuffer->write(temp, chunk);
          if (w == LIBSSH2_ERROR_CHANNEL_CLOSED ||
              w == LIBSSH2_ERROR_SOCKET_SEND ||
              w == LIBSSH2_ERROR_SOCKET_RECV) {
            dropPending = true;
            dropReason =
                String("ssh drain failure (code=") + String((int)w) + ")";
            dropCode = (int)w;
            writeBroken = true;
            ch.gracefulClosing = true;
            ch.remoteEof = true;
          }
          break;
        }
      }
      unlockSession();
    }

    if (totalWritten > 0) {
      if (lockStats()) {
        bytesSent += totalWritten;
        unlockStats();
      }
      LOGF_I("SSH", "Channel %d: Drained %zu bytes in %d passes, %zu queued",
             channelIndex, totalWritten, passes, ch.queuedBytesToRemote);
      success = true;
    }

    // 2) Read local socket if backpressure acceptable (suppress when burst >=2
    // or terminal)
    bool suppressLocalRead = false;
    if (ch.terminalSocketFailure) {
      suppressLocalRead = true;
      if ((now - ch.lastErrorDetailLogMs) > 1000) {
        ch.lastErrorDetailLogMs = now;
        LOGF_D("SSH", "Channel %d: Local read suppressed (terminal failure)",
               channelIndex);
      }
    }
    if (!suppressLocalRead && ch.localReadTerminated) {
      suppressLocalRead = true;
      if ((now - ch.lastErrorDetailLogMs) > 1000) {
        ch.lastErrorDetailLogMs = now;
        LOGF_D("SSH", "Channel %d: Local read suppressed (localReadTerminated)",
               channelIndex);
      }
    } else if (!suppressLocalRead && ch.socketRecvBurstCount >= 2) {
      suppressLocalRead = true; // early limitation
      if ((now - ch.lastErrorDetailLogMs) > 1000) {
        ch.lastErrorDetailLogMs = now;
        LOGF_D("SSH", "Channel %d: Local read suppressed (burst=%d)",
               channelIndex, ch.socketRecvBurstCount);
      }
    }
    if (!suppressLocalRead && ch.localReadPaused) {
      suppressLocalRead = true;
    }
    if (!suppressLocalRead && ch.localSocket >= 0) {
      int sockError = 0;
      socklen_t errLen = sizeof(sockError);
      if (getsockopt(ch.localSocket, SOL_SOCKET, SO_ERROR, &sockError,
                     &errLen) == 0 &&
          sockError != 0) {
        bool benignReset = (sockError == ECONNRESET || sockError == ENOTCONN ||
                            sockError == EPIPE || sockError == ESHUTDOWN ||
                            sockError == ECONNABORTED);
        unsigned long nowErr = millis();
        if (benignReset) {
          if ((nowErr - ch.lastErrorDetailLogMs) > 1000) {
            ch.lastErrorDetailLogMs = nowErr;
            LOGF_I("SSH", "Channel %d: Local socket error before read: %s",
                   channelIndex, strerror(sockError));
          }
          ch.gracefulClosing = true;
          ch.localReadTerminated = true;
          LOGF_I("SSH",
                 "Channel %d: Graceful close due to benign local error (%s) "
                 "queuedR=%zu",
                 channelIndex, strerror(sockError), ch.queuedBytesToRemote);
        } else {
          if ((nowErr - ch.lastErrorDetailLogMs) > 1000) {
            ch.lastErrorDetailLogMs = nowErr;
            LOGF_W("SSH",
                   "Channel %d: Local socket error before read: %s (errno=%d)",
                   channelIndex, strerror(sockError), sockError);
          }
          ch.consecutiveErrors++;
        }
        if (ch.localSocket >= 0) {
          shutdown(ch.localSocket, SHUT_RD);
        }
        suppressLocalRead = true;
      }
    }
    if (!suppressLocalRead && globalRateLimitBytesPerSec != 0) {
      size_t allowance = getGlobalAllowance(MIN_WRITE_SIZE);
      if (allowance == 0) {
        throttledByGlobalLimit = true;
        ch.lastActivity = millis();
        if (channelIndex < (int)lastThrottleLog.size() &&
            (now - lastThrottleLog[channelIndex] > 1000)) {
          lastThrottleLog[channelIndex] = now;
          LOGF_D("SSH",
                 "Channel %d: Global limiter delaying local read (queued=%zu)",
                 channelIndex, ch.queuedBytesToRemote);
        }
        suppressLocalRead = true;
      }
    }
    pendingToRemote = getPendingToRemoteBytes(ch);
    if (!suppressLocalRead && pendingToRemote < highWaterLocal &&
        isSocketReadable(ch.localSocket, 5)) {
      ssize_t localRead =
          recv(ch.localSocket, txBuffer, bufferSize, MSG_DONTWAIT);
      if (localRead > 0) {
        // Attempt immediate looped write (direct drainage)
        size_t offset = 0;
        int directPass = 0;
        size_t directWrittenTotal = 0;
        String directErrorDetail = "";
        bool sessionLocked = lockSession(pdMS_TO_TICKS(200));
        if (sessionLocked) {
          while (offset < (size_t)localRead &&
                 directPass < SSH_MAX_WRITES_PER_PASS) {
            size_t remain = (size_t)localRead - offset;
            size_t allowance = getGlobalAllowance(remain);
            if (allowance == 0 && globalRateLimitBytesPerSec != 0) {
              throttledByGlobalLimit = true;
              ch.lastActivity = millis();
              if (channelIndex < (int)lastThrottleLog.size() &&
                  (now - lastThrottleLog[channelIndex] > 1000)) {
                lastThrottleLog[channelIndex] = now;
                LOGF_D("SSH",
                       "Channel %d: Global limiter delaying direct write "
                       "(remain=%zu queued=%zu)",
                       channelIndex, remain, ch.queuedBytesToRemote);
              }
              break;
            }
            remain = allowance;
            ssize_t w = libssh2_channel_write_ex(
                ch.channel, 0, (char *)txBuffer + offset, remain);
            if (w > 0) {
              offset += w;
              directPass++;
              directWrittenTotal += w;
              ch.totalBytesSent += w;
              ch.lastSuccessfulWrite = now;
              ch.consecutiveErrors = 0;
              if (lockStats()) {
                bytesSent += w;
                unlockStats();
              }
              ch.lastActivity = millis();
              commitGlobalTokens((size_t)w);
            } else if (w == LIBSSH2_ERROR_EAGAIN) {
              ch.lastActivity = millis();
              break; // Queue the remainder
            } else {
              ch.consecutiveErrors++;
              ch.lastWriteErrorMs = now;
              if (w == LIBSSH2_ERROR_SOCKET_RECV) {
                ch.socketRecvErrors++;
                if (ch.socketRecvBurstCount == 0)
                  ch.firstSocketRecvErrorMs = now;
                ch.socketRecvBurstCount++;
                if (!ch.terminalSocketFailure &&
                    ch.socketRecvBurstCount >= SOCKET_RECV_BURST_THRESHOLD &&
                    (now - ch.firstSocketRecvErrorMs) <=
                        SOCKET_RECV_BURST_WINDOW_MS) {
                  ch.terminalSocketFailure = true;
                  ch.gracefulClosing = true;
                  LOGF_W("SSH",
                         "Channel %d: Terminal -43 burst (direct) count=%d "
                         "window=%lums qRemote=%zu",
                         channelIndex, ch.socketRecvBurstCount,
                         (now - ch.firstSocketRecvErrorMs),
                         ch.queuedBytesToRemote);
                  emitChannelError(channelIndex, TunnelErrorCode::SshSocketRecv,
                                   (int)w, "terminal -43 recv burst (direct)");
                  emitChannelWriteBroken(channelIndex,
                                         TunnelErrorCode::SshSocketRecv, (int)w,
                                         "terminal -43 recv burst (direct)");
                  recordTerminalSocketFailure(now);
                } else if (!ch.terminalSocketFailure) {
                  if ((now - ch.lastErrorDetailLogMs) > 2000) {
                    ch.lastErrorDetailLogMs = now;
                    LOGF_W("SSH",
                           "Channel %d: -43 recv (direct) burst=%d qRemote=%zu",
                           channelIndex, ch.socketRecvBurstCount,
                           ch.queuedBytesToRemote);
                    emitChannelError(channelIndex,
                                     TunnelErrorCode::SshSocketRecv, (int)w,
                                     "ssh direct recv error (-43)");
                  }
                }
              } else if (w == LIBSSH2_ERROR_DECRYPT) {
                ch.fatalCryptoErrors++;
                ch.gracefulClosing = true;
              }
              char *errmsg = nullptr;
              int errlen = 0;
              libssh2_session_last_error(session, &errmsg, &errlen, 0);
              if (errmsg && errlen > 0) {
                directErrorDetail = String(errmsg).substring(0, errlen);
              }
              if (now - ch.lastErrorDetailLogMs > 2000) {
                ch.lastErrorDetailLogMs = now;
                const char *detail = directErrorDetail.length()
                                         ? directErrorDetail.c_str()
                                         : "unknown";
                LOGF_W("SSH",
                       "Channel %d: Direct write err %zd cons=%d sockRecv=%d "
                       "crypt=%d remain=%zu detail=%s",
                       channelIndex, w, ch.consecutiveErrors,
                       ch.socketRecvErrors, ch.fatalCryptoErrors,
                       (size_t)localRead - offset, detail);
                char errMsg[128];
                snprintf(errMsg, sizeof(errMsg),
                         "ssh direct write err=%zd detail=%s", w, detail);
                emitChannelError(channelIndex, mapSshErrorToCode((int)w, true),
                                 (int)w, errMsg);
              }
              if (w == LIBSSH2_ERROR_CHANNEL_CLOSED ||
                  w == LIBSSH2_ERROR_SOCKET_SEND ||
                  w == LIBSSH2_ERROR_SOCKET_RECV) {
                dropPending = true;
                dropReason = String("ssh direct write failure (code=") +
                             String((int)w) + ")";
                dropCode = (int)w;
                writeBroken = true;
                ch.gracefulClosing = true;
                ch.remoteEof = true;
              }
              break;
            }
          }
          unlockSession();
        }
        size_t remaining = (size_t)localRead - offset;
        if (remaining > 0) {
          size_t q =
              queueData(channelIndex, txBuffer + offset, remaining, false);
          if (q < remaining) {
            size_t leftover = remaining - q;
            size_t unqueuedOffset = offset + q;
            size_t existingRemain = 0;
            if (ch.deferredToRemote) {
              existingRemain =
                  ch.deferredToRemoteSize - ch.deferredToRemoteOffset;
            }
            uint8_t *newBuf = (uint8_t *)safeMalloc(existingRemain + leftover,
                                                    "DEFER_REM_TX");
            if (newBuf) {
              size_t pos = 0;
              if (existingRemain > 0) {
                memcpy(newBuf, ch.deferredToRemote + ch.deferredToRemoteOffset,
                       existingRemain);
                pos += existingRemain;
              }
              memcpy(newBuf + pos, txBuffer + unqueuedOffset, leftover);
              SAFE_FREE(ch.deferredToRemote);
              ch.deferredToRemote = newBuf;
              ch.deferredToRemoteSize = existingRemain + leftover;
              ch.deferredToRemoteOffset = 0;
              LOGF_W("SSH",
                     "Channel %d: Deferred %zu bytes (Local->SSH) qRemote=%zu "
                     "cons=%d",
                     channelIndex, leftover, ch.queuedBytesToRemote,
                     ch.consecutiveErrors);
            } else {
              LOGF_E("SSH",
                     "Channel %d: Allocation failed deferring %zu bytes (drop)",
                     channelIndex, leftover);
              char dropMsg[128];
              snprintf(dropMsg, sizeof(dropMsg),
                       "alloc failed deferring %zu bytes (ssh->local)",
                       leftover);
              emitChannelError(channelIndex, TunnelErrorCode::DropLocalToSsh,
                               ENOMEM, dropMsg);
              ch.lostWriteChunks++;
              ch.bytesDropped += leftover;
              if (lockStats()) {
                droppedBytes += leftover;
                unlockStats();
              }
            }
          }
          success =
              true; // what was written + any enqueued remainder is preserved
        }
        if (directWrittenTotal > 0) {
          LOGF_D("SSH", "Channel %d: Direct wrote %zu/%zd bytes (+%zu queued)",
                 channelIndex, directWrittenTotal, localRead, remaining);
        }
      } else if (localRead == 0) {
        LOGF_I("SSH",
               "Channel %d: Local socket closed (remoteEof=%d queuedR=%zu "
               "queuedL=%zu)",
               channelIndex, ch.remoteEof ? 1 : 0, ch.queuedBytesToRemote,
               ch.queuedBytesToLocal);
        ch.gracefulClosing = true;
        ch.localReadTerminated = true;
        if (ch.localSocket >= 0) {
          shutdown(ch.localSocket, SHUT_RD);
        }
      } else if (localRead < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOGF_W("SSH", "Channel %d: Local read error %s", channelIndex,
               strerror(errno));
        ch.consecutiveErrors++;
        ch.gracefulClosing = true;
        ch.localReadTerminated = true;
        if (ch.localSocket >= 0) {
          shutdown(ch.localSocket, SHUT_RD);
        }
      }
    } else if (suppressLocalRead) {
      if ((now - ch.lastErrorDetailLogMs) > 2000) {
        ch.lastErrorDetailLogMs = now;
        LOGF_D("SSH",
               "Channel %d: Local read suppressed (burst=%d terminal=%d "
               "qRemote=%zu)",
               channelIndex, ch.socketRecvBurstCount,
               ch.terminalSocketFailure ? 1 : 0, ch.queuedBytesToRemote);
      }
    }
  }

  if (throttledByGlobalLimit && ch.queuedBytesToRemote > 0) {
    success = true;
    ch.lastActivity = now;
  }

  if (dropPending) {
    size_t droppedBytesLocal = 0;
    if (ch.localToSshBuffer) {
      droppedBytesLocal += ch.localToSshBuffer->size();
      ch.localToSshBuffer->clear();
      ch.queuedBytesToRemote = 0;
    }
    if (ch.deferredToRemote) {
      size_t remain =
          (ch.deferredToRemoteSize > ch.deferredToRemoteOffset)
              ? (ch.deferredToRemoteSize - ch.deferredToRemoteOffset)
              : 0;
      droppedBytesLocal += remain;
      SAFE_FREE(ch.deferredToRemote);
      ch.deferredToRemote = nullptr;
      ch.deferredToRemoteSize = 0;
      ch.deferredToRemoteOffset = 0;
    }
    const char *reason =
        dropReason.length() ? dropReason.c_str() : "ssh write failure";
    if (droppedBytesLocal > 0) {
      ch.bytesDropped += droppedBytesLocal;
      if (lockStats()) {
        droppedBytes += droppedBytesLocal;
        unlockStats();
      }
      LOGF_W("SSH", "Channel %d: Dropped %zu bytes pending to remote (%s)",
             channelIndex, droppedBytesLocal, reason);
      char dropMsg[160];
      snprintf(dropMsg, sizeof(dropMsg), "dropped %zu bytes to remote (%s)",
               droppedBytesLocal, reason);
      emitChannelError(channelIndex, TunnelErrorCode::DropLocalToSsh, dropCode,
                       dropMsg);
      if (writeBroken) {
        TunnelErrorCode brokenCode = dropCode
                                         ? mapSshErrorToCode(dropCode, true)
                                         : TunnelErrorCode::SshWriteFailure;
        emitChannelWriteBroken(channelIndex, brokenCode, dropCode, dropMsg);
      }
    } else if (writeBroken) {
      TunnelErrorCode brokenCode = dropCode ? mapSshErrorToCode(dropCode, true)
                                            : TunnelErrorCode::SshWriteFailure;
      char brokenMsg[160];
      snprintf(brokenMsg, sizeof(brokenMsg), "write broken (%s)", reason);
      emitChannelWriteBroken(channelIndex, brokenCode, dropCode, brokenMsg);
    }
    if (ch.localSocket >= 0) {
      shutdown(ch.localSocket, SHUT_RDWR);
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
  static std::vector<unsigned long> lastProcessTime;
  int maxTrackedChannels = config->getConnectionConfig().maxChannels;
  int neededSize = std::max(maxTrackedChannels, channelIndex + 1);
  if ((int)lastProcessTime.size() < neededSize) {
    lastProcessTime.assign(neededSize, 0);
  }
  if (channelIndex < (int)lastProcessTime.size() &&
      (now - lastProcessTime[channelIndex]) < 20) { // 20ms instead of 10ms
    return;
  }
  if (channelIndex < (int)lastProcessTime.size()) {
    lastProcessTime[channelIndex] = now;
  }

  // 1) Process SSH->Local buffer (sshToLocalBuffer) - FIXED timeout
  if (xSemaphoreTake(ch.readMutex, pdMS_TO_TICKS(100)) ==
      pdTRUE) { // 100ms instead of 20ms
    if (ch.sshToLocalBuffer && !ch.sshToLocalBuffer->empty() &&
        ch.localSocket >= 0 && isSocketWritable(ch.localSocket, 5)) {

      uint8_t tempBuffer[SSH_BUFFER_SIZE];
      size_t bytesRead =
          ch.sshToLocalBuffer->read(tempBuffer, sizeof(tempBuffer));

      if (bytesRead > 0) {
        ssize_t written =
            send(ch.localSocket, tempBuffer, bytesRead, MSG_DONTWAIT);

        if (written > 0) {
          ch.totalBytesReceived += written;
          ch.queuedBytesToLocal = (ch.queuedBytesToLocal > written)
                                      ? ch.queuedBytesToLocal - written
                                      : 0;
          ch.consecutiveErrors = 0; // Reset on success
          if (lockStats()) {
            bytesReceived += written;
            unlockStats();
          }
          ch.lastActivity = millis();

          // If not all sent, put remainder back in buffer
          if (written < bytesRead) {
            ch.sshToLocalBuffer->write(tempBuffer + written,
                                       bytesRead - written);
            ch.lastActivity = millis();
          }

          LOGF_D("SSH",
                 "Channel %d: Processed %zd/%zu bytes from SSH->Local buffer",
                 channelIndex, written, bytesRead);
        } else if (written < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ch.sshToLocalBuffer->write(tempBuffer, bytesRead);
            ch.eagainErrors++;
            if ((ch.eagainErrors % 32) == 1) {
              LOGF_D("SSH",
                     "Channel %d: Socket busy, preserved=%zu (eagain=%d)",
                     channelIndex, bytesRead, ch.eagainErrors);
            }
            ch.lastActivity = millis();
          } else {
            ch.sshToLocalBuffer->write(tempBuffer, bytesRead);
            ch.consecutiveErrors++;
            LOGF_W(
                "SSH",
                "Channel %d: Error writing from SSH->Local buffer: %s (err=%d)",
                channelIndex, strerror(errno), ch.consecutiveErrors);
            char errMsg[128];
            snprintf(errMsg, sizeof(errMsg),
                     "local send err=%d %s (ssh->local buffer)", errno,
                     strerror(errno));
            emitChannelError(channelIndex, TunnelErrorCode::LocalSocketError,
                             errno, errMsg);
            ch.lastActivity = millis();
          }
        } else {
          // written == 0 - socket closed on receive side
          ch.sshToLocalBuffer->write(tempBuffer, bytesRead);
          LOGF_I("SSH", "Channel %d: Local socket closed, %zu bytes preserved",
                 channelIndex, bytesRead);
          ch.lastActivity = millis();
        }
      }
    }
    xSemaphoreGive(ch.readMutex);
  } else {
    ch.readMutexFailures++;
    if ((ch.readMutexFailures % 64) == 1) {
      LOGF_D("SSH", "Channel %d: Read mutex busy (failures=%d)", channelIndex,
             ch.readMutexFailures);
    }
  }

  // 2) Process Local->SSH buffer (localToSshBuffer) - FIXED timeout
  static std::vector<unsigned long> pendingThrottleLog;
  int pendingNeeded =
      std::max(config->getConnectionConfig().maxChannels, channelIndex + 1);
  if ((int)pendingThrottleLog.size() < pendingNeeded) {
    pendingThrottleLog.assign(pendingNeeded, 0);
  }
  if (xSemaphoreTake(ch.writeMutex, pdMS_TO_TICKS(100)) ==
      pdTRUE) { // 100ms instead of 20ms
    bool dropPending = false;
    String dropReason = "";
    int dropCode = 0;
    bool writeBroken = false;
    if (ch.localToSshBuffer && !ch.localToSshBuffer->empty() && ch.channel) {
      const int maxWritesThisPass =
          6; // Conservative per-loop drain cap (overrides global macro 8)
      int passes = 0;
      size_t totalWrittenThisPass = 0;
      if (lockSession(pdMS_TO_TICKS(200))) {
        while (passes < maxWritesThisPass && !ch.localToSshBuffer->empty()) {
          uint8_t tempBuffer[SSH_BUFFER_SIZE];
          size_t bytesRead =
              ch.localToSshBuffer->read(tempBuffer, sizeof(tempBuffer));
          if (bytesRead == 0)
            break;
          if (bytesRead < MIN_WRITE_SIZE && !ch.localToSshBuffer->empty()) {
            size_t extra = ch.localToSshBuffer->read(
                tempBuffer + bytesRead, MIN_WRITE_SIZE - bytesRead);
            bytesRead += extra;
          }
          size_t allowance = getGlobalAllowance(bytesRead);
          if (allowance == 0 && globalRateLimitBytesPerSec != 0) {
            ch.localToSshBuffer->write(tempBuffer, bytesRead);
            ch.lastActivity = millis();
            if (channelIndex < (int)pendingThrottleLog.size() &&
                (now - pendingThrottleLog[channelIndex] > 1000)) {
              pendingThrottleLog[channelIndex] = now;
              LOGF_D("SSH",
                     "Channel %d: Global limiter delaying buffered drain "
                     "(queued=%zu)",
                     channelIndex, ch.queuedBytesToRemote);
            }
            break;
          }
          if (allowance < bytesRead) {
            ch.localToSshBuffer->write(tempBuffer + allowance,
                                       bytesRead - allowance);
            bytesRead = allowance;
            ch.lastActivity = millis();
          }
          String writeErrorDetail = "";
          ssize_t written =
              libssh2_channel_write(ch.channel, (char *)tempBuffer, bytesRead);
          if (written > 0) {
            passes++;
            totalWrittenThisPass += written;
            ch.totalBytesSent += written;
            ch.queuedBytesToRemote = (ch.queuedBytesToRemote > written)
                                         ? ch.queuedBytesToRemote - written
                                         : 0;
            ch.consecutiveErrors = 0;
            if (lockStats()) {
              bytesSent += written;
              unlockStats();
            }
            ch.lastActivity = millis();
            commitGlobalTokens((size_t)written);
            if ((size_t)written < bytesRead) {
              ch.localToSshBuffer->write(tempBuffer + written,
                                         bytesRead - written);
              ch.lastActivity = millis();
              break; // Reduced SSH window: stop draining
            }
          } else if (written == LIBSSH2_ERROR_EAGAIN) {
            ch.localToSshBuffer->write(tempBuffer, bytesRead);
            ch.eagainErrors++;
            if ((ch.eagainErrors % 32) == 1) {
              LOGF_D("SSH",
                     "Channel %d: SSH channel busy mid-drain (eagain=%d "
                     "passes=%d total=%zu)",
                     channelIndex, ch.eagainErrors, passes,
                     totalWrittenThisPass);
              emitChannelError(channelIndex, TunnelErrorCode::SshEagain,
                               (int)written, "ssh channel busy mid-drain");
            }
            ch.lastActivity = millis();
            break; // SSH window full
          } else if (written == 0) {
            ch.localToSshBuffer->write(tempBuffer, bytesRead);
            LOGF_I("SSH", "Channel %d: SSH channel closed, %zu bytes preserved",
                   channelIndex, bytesRead);
            ch.lastActivity = millis();
            break;
          } else {
            char *errmsg = nullptr;
            int errlen = 0;
            libssh2_session_last_error(session, &errmsg, &errlen, 0);
            if (errmsg && errlen > 0) {
              writeErrorDetail = String(errmsg).substring(0, errlen);
            }
            ch.localToSshBuffer->write(tempBuffer, bytesRead);
            ch.consecutiveErrors++;
            const char *detail = writeErrorDetail.length()
                                     ? writeErrorDetail.c_str()
                                     : "unknown";
            LOGF_W("SSH", "Channel %d: Write error %zd (err=%d, detail=%s)",
                   channelIndex, written, ch.consecutiveErrors, detail);
            char errMsg[128];
            snprintf(errMsg, sizeof(errMsg), "ssh write err=%zd detail=%s",
                     written, detail);
            emitChannelError(channelIndex,
                             mapSshErrorToCode((int)written, true),
                             (int)written, errMsg);
            if (written == LIBSSH2_ERROR_CHANNEL_CLOSED ||
                written == LIBSSH2_ERROR_SOCKET_SEND ||
                written == LIBSSH2_ERROR_SOCKET_RECV) {
              dropPending = true;
              dropReason = String("ssh drain failure (code=") +
                           String((int)written) + ")";
              dropCode = (int)written;
              writeBroken = true;
            }
            break;
          }
        }
        unlockSession();
      }
      if (totalWrittenThisPass > 0) {
        LOGF_D("SSH",
               "Channel %d: Drained %zu bytes in %d passes (queuedRemote=%zu)",
               channelIndex, totalWrittenThisPass, passes,
               ch.queuedBytesToRemote);
      }
    }

    if (dropPending) {
      size_t droppedBytesLocal = 0;
      if (ch.localToSshBuffer) {
        droppedBytesLocal += ch.localToSshBuffer->size();
        ch.localToSshBuffer->clear();
        ch.queuedBytesToRemote = 0;
      }
      if (ch.deferredToRemote) {
        size_t remain =
            (ch.deferredToRemoteSize > ch.deferredToRemoteOffset)
                ? (ch.deferredToRemoteSize - ch.deferredToRemoteOffset)
                : 0;
        droppedBytesLocal += remain;
        SAFE_FREE(ch.deferredToRemote);
        ch.deferredToRemote = nullptr;
        ch.deferredToRemoteSize = 0;
        ch.deferredToRemoteOffset = 0;
      }
      const char *reason =
          dropReason.length() ? dropReason.c_str() : "ssh write failure";
      if (droppedBytesLocal > 0) {
        ch.bytesDropped += droppedBytesLocal;
        if (lockStats()) {
          droppedBytes += droppedBytesLocal;
          unlockStats();
        }
        LOGF_W("SSH", "Channel %d: Dropped %zu bytes pending to remote (%s)",
               channelIndex, droppedBytesLocal, reason);
        char dropMsg[160];
        snprintf(dropMsg, sizeof(dropMsg), "dropped %zu bytes to remote (%s)",
                 droppedBytesLocal, reason);
        emitChannelError(channelIndex, TunnelErrorCode::DropLocalToSsh,
                         dropCode, dropMsg);
        if (writeBroken) {
          TunnelErrorCode brokenCode = dropCode
                                           ? mapSshErrorToCode(dropCode, true)
                                           : TunnelErrorCode::SshWriteFailure;
          emitChannelWriteBroken(channelIndex, brokenCode, dropCode, dropMsg);
        }
      } else if (writeBroken) {
        TunnelErrorCode brokenCode = dropCode
                                         ? mapSshErrorToCode(dropCode, true)
                                         : TunnelErrorCode::SshWriteFailure;
        char brokenMsg[160];
        snprintf(brokenMsg, sizeof(brokenMsg), "write broken (%s)", reason);
        emitChannelWriteBroken(channelIndex, brokenCode, dropCode, brokenMsg);
      }
      ch.gracefulClosing = true;
      ch.remoteEof = true;
      if (ch.localSocket >= 0) {
        shutdown(ch.localSocket, SHUT_RDWR);
      }
    }
    xSemaphoreGive(ch.writeMutex);
  } else {
    ch.writeMutexFailures++;
    if ((ch.writeMutexFailures % 64) == 1) {
      LOGF_D("SSH", "Channel %d: Write mutex busy (failures=%d)", channelIndex,
             ch.writeMutexFailures);
    }
  }

  // 3) Resume flow control if we've dropped below the LOW watermark
  const size_t lowWaterLocal = getLowWaterLocal();
  if (ch.flowControlPaused && ch.queuedBytesToLocal < lowWaterLocal) {
    ch.flowControlPaused = false;
    LOGF_D("SSH", "Channel %d: Flow control resumed (below %zu bytes)",
           channelIndex, lowWaterLocal);
  }
}

bool SSHTunnel::queueData(int channelIndex, uint8_t *data, size_t size,
                          bool isRead) {
  size_t q = queueData(channelIndex, (const uint8_t *)data, size, isRead);
  return q == size;
}

//   queueData version returning the number of bytes actually enqueued
size_t SSHTunnel::queueData(int channelIndex, const uint8_t *data, size_t size,
                            bool isRead) {
  if (channelIndex < 0 ||
      channelIndex >= config->getConnectionConfig().maxChannels)
    return 0;
  if (!data || size == 0)
    return 0;
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active)
    return 0;
  static std::vector<unsigned long> lastQueueHighLogToLocal;
  static std::vector<unsigned long> lastQueueHighLogToRemote;
  int neededLogs =
      std::max(config->getConnectionConfig().maxChannels, channelIndex + 1);
  if ((int)lastQueueHighLogToLocal.size() < neededLogs) {
    lastQueueHighLogToLocal.assign(neededLogs, 0);
  }
  if ((int)lastQueueHighLogToRemote.size() < neededLogs) {
    lastQueueHighLogToRemote.assign(neededLogs, 0);
  }
  DataRingBuffer *targetBuffer =
      isRead ? ch.sshToLocalBuffer : ch.localToSshBuffer;
  SemaphoreHandle_t mutex = isRead ? ch.readMutex : ch.writeMutex;
  bool locked = false;
  bool tookLock = false;
  if (mutex) {
    TaskHandle_t holder = xSemaphoreGetMutexHolder(mutex);
    if (holder == xTaskGetCurrentTaskHandle()) {
      // Caller already owns the mutex in this task; reuse that ownership.
      locked = true;
    } else {
      locked = (xSemaphoreTake(mutex, pdMS_TO_TICKS(20)) == pdTRUE);
      tookLock = locked;
    }
  }
  if (mutex && !locked) {
    if (isRead) {
      ch.readMutexFailures++;
      if ((ch.readMutexFailures % 64) == 1) {
        LOGF_D("SSH",
               "Channel %d: queueData read mutex busy (failures=%d)",
               channelIndex, ch.readMutexFailures);
      }
    } else {
      ch.writeMutexFailures++;
      if ((ch.writeMutexFailures % 64) == 1) {
        LOGF_D("SSH",
               "Channel %d: queueData write mutex busy (failures=%d)",
               channelIndex, ch.writeMutexFailures);
      }
    }
    return 0;
  }
  // We either acquired the mutex or already own it in this task.
  size_t remaining = size;
  const uint8_t *cursor = data;
  size_t totalQueued = 0;
  while (remaining > 0) {
    size_t chunk = remaining > SSH_BUFFER_SIZE ? SSH_BUFFER_SIZE : remaining;
    size_t w = targetBuffer->write(cursor, chunk);
    if (w == 0)
      break;
    totalQueued += w;
    remaining -= w;
    cursor += w;
    if (isRead)
      ch.queuedBytesToLocal += w;
    else
      ch.queuedBytesToRemote += w;
  }
  ch.lastActivity = millis();
  const size_t highWaterLocal = getHighWaterLocal();
  if (channelIndex < (int)lastQueueHighLogToLocal.size() && totalQueued > 0) {
    unsigned long nowDiag = millis();
    if (isRead) {
      if (ch.queuedBytesToLocal > highWaterLocal &&
          (nowDiag - lastQueueHighLogToLocal[channelIndex] > 2000)) {
        lastQueueHighLogToLocal[channelIndex] = nowDiag;
        LOGF_D("SSH",
               "Channel %d: Queue high watermark (toLocal=%zu, toRemote=%zu)",
               channelIndex, ch.queuedBytesToLocal, ch.queuedBytesToRemote);
      }
    } else {
      if (ch.queuedBytesToRemote > highWaterLocal &&
          (nowDiag - lastQueueHighLogToRemote[channelIndex] > 2000)) {
        lastQueueHighLogToRemote[channelIndex] = nowDiag;
        LOGF_D("SSH",
               "Channel %d: Queue high watermark (toLocal=%zu, toRemote=%zu)",
               channelIndex, ch.queuedBytesToLocal, ch.queuedBytesToRemote);
      }
    }
  }
  if (tookLock)
    xSemaphoreGive(mutex);
  if (totalQueued == 0) {
    ch.lostWriteChunks++;
    if (ch.lostWriteChunks % 10 == 1) {
      LOGF_W("SSH",
             "Channel %d: Buffer full - 0 bytes enqueued (lostChunks=%d)",
             channelIndex, ch.lostWriteChunks);
    }
  }
  return totalQueued;
}

void SSHTunnel::flushPendingData(int channelIndex) {
  if (channelIndex < 0 ||
      channelIndex >= config->getConnectionConfig().maxChannels)
    return;
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active)
    return;

  // 1. Attempt to drain deferred buffers into ring buffers
  if (ch.deferredToLocal && ch.deferredToLocalOffset < ch.deferredToLocalSize) {
    size_t remain = ch.deferredToLocalSize - ch.deferredToLocalOffset;
    size_t q =
        queueData(channelIndex, ch.deferredToLocal + ch.deferredToLocalOffset,
                  remain, true);
    ch.deferredToLocalOffset += q;
    if (ch.deferredToLocalOffset >= ch.deferredToLocalSize) {
      SAFE_FREE(ch.deferredToLocal);
      ch.deferredToLocal = nullptr;
      ch.deferredToLocalSize = ch.deferredToLocalOffset = 0;
    }
  }
  if (ch.deferredToRemote &&
      ch.deferredToRemoteOffset < ch.deferredToRemoteSize) {
    size_t remain = ch.deferredToRemoteSize - ch.deferredToRemoteOffset;
    size_t q =
        queueData(channelIndex, ch.deferredToRemote + ch.deferredToRemoteOffset,
                  remain, false);
    ch.deferredToRemoteOffset += q;
    if (ch.deferredToRemoteOffset >= ch.deferredToRemoteSize) {
      SAFE_FREE(ch.deferredToRemote);
      ch.deferredToRemote = nullptr;
      ch.deferredToRemoteSize = ch.deferredToRemoteOffset = 0;
    }
  }

  // 2. SSH->Local ring vers socket
  if (ch.sshToLocalBuffer && !ch.sshToLocalBuffer->empty() &&
      ch.localSocket >= 0) {
    if (lockChannelRead(channelIndex)) {
      const uint8_t *chunkPtr = nullptr;
      size_t chunkSize =
          ch.sshToLocalBuffer->acquire(&chunkPtr, SSH_BUFFER_SIZE);
      if (chunkSize > 0 && chunkPtr) {
        size_t sentTotal = 0;
        while (sentTotal < chunkSize) {
          ssize_t w = send(ch.localSocket, chunkPtr + sentTotal,
                           chunkSize - sentTotal, MSG_DONTWAIT);
          if (w > 0) {
            sentTotal += (size_t)w;
          } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break; // socket temporarily full
          } else {
            LOGF_W("SSH", "Channel %d: flushPendingData local send err %s",
                   channelIndex, strerror(errno));
            char errMsg[128];
            snprintf(errMsg, sizeof(errMsg), "flush local send err=%d %s",
                     errno, strerror(errno));
            emitChannelError(channelIndex, TunnelErrorCode::LocalSocketError,
                             errno, errMsg);
            break;
          }
        }

        // Update counters for bytes actually delivered
        if (sentTotal > 0) {
          ch.totalBytesReceived += sentTotal;
          if (lockStats()) {
            bytesReceived += sentTotal;
            unlockStats();
          }
        }

        // If not everything was written, stash remainder into deferred buffer
        size_t remaining = chunkSize - sentTotal;
        if (remaining > 0) {
          uint8_t *newBuf = (uint8_t *)safeMalloc(remaining, "DEFER_LOC_FLUSH");
          if (newBuf) {
            memcpy(newBuf, chunkPtr + sentTotal, remaining);
            SAFE_FREE(ch.deferredToLocal);
            ch.deferredToLocal = newBuf;
            ch.deferredToLocalSize = remaining;
            ch.deferredToLocalOffset = 0;
            LOGF_W("SSH",
                   "Channel %d: Deferred %zu bytes during flush (SSH->Local)",
                   channelIndex, remaining);
          } else {
            LOGF_E("SSH",
                   "Channel %d: Allocation failed deferring %zu bytes (drop)",
                   channelIndex, remaining);
            char dropMsg[128];
            snprintf(dropMsg, sizeof(dropMsg),
                     "alloc failed deferring %zu bytes (ssh->local flush)",
                     remaining);
            emitChannelError(channelIndex, TunnelErrorCode::DropSshToLocal,
                             ENOMEM, dropMsg);
            ch.bytesDropped += remaining;
            if (lockStats()) {
              droppedBytes += remaining;
              unlockStats();
            }
          }
        }

        // Release the chunk back to the ringbuffer
        ch.sshToLocalBuffer->release(chunkPtr);
        // Ring buffer no longer holds this chunk
        ch.queuedBytesToLocal = (ch.queuedBytesToLocal > chunkSize)
                                    ? (ch.queuedBytesToLocal - chunkSize)
                                    : 0;
      }
      unlockChannelRead(channelIndex);
    }
  }

  // 3. Local->SSH ring vers SSH
  if (ch.localToSshBuffer && !ch.localToSshBuffer->empty() && ch.channel) {
    if (lockChannelWrite(channelIndex)) {
      bool dropPending = false;
      String dropReason = "";
      int dropCode = 0;
      bool writeBroken = false;
      const uint8_t *chunkPtr = nullptr;
      size_t chunkSize =
          ch.localToSshBuffer->acquire(&chunkPtr, SSH_BUFFER_SIZE);
      if (chunkSize > 0 && chunkPtr) {
        size_t sentTotal = 0;
        while (sentTotal < chunkSize) {
          ssize_t w = libssh2_channel_write_ex(ch.channel, 0,
                                               (char *)(chunkPtr + sentTotal),
                                               chunkSize - sentTotal);
          if (w > 0) {
            sentTotal += (size_t)w;
            ch.lastSuccessfulWrite = millis();
            ch.consecutiveErrors = 0;
          } else if (w == LIBSSH2_ERROR_EAGAIN) {
            break; // try later
          } else {
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
              LOGF_W("SSH",
                     "Channel %d: flushPendingData SSH write err %zd cons=%d "
                     "sockRecv=%d crypt=%d qRemote=%zu defRem=%zu",
                     channelIndex, w, ch.consecutiveErrors, ch.socketRecvErrors,
                     ch.fatalCryptoErrors, ch.queuedBytesToRemote,
                     (size_t)(ch.deferredToRemote ? (ch.deferredToRemoteSize -
                                                     ch.deferredToRemoteOffset)
                                                  : 0));
              char errMsg[128];
              snprintf(errMsg, sizeof(errMsg),
                       "ssh flush write err=%zd qRemote=%zu", w,
                       ch.queuedBytesToRemote);
              emitChannelError(channelIndex, mapSshErrorToCode((int)w, true),
                               (int)w, errMsg);
            }
            if (w == LIBSSH2_ERROR_CHANNEL_CLOSED ||
                w == LIBSSH2_ERROR_SOCKET_SEND ||
                w == LIBSSH2_ERROR_SOCKET_RECV) {
              dropPending = true;
              dropReason =
                  String("ssh flush failure (code=") + String((int)w) + ")";
              dropCode = (int)w;
              writeBroken = true;
            }
            break;
          }
        }

        size_t remaining = chunkSize - sentTotal;
        if (remaining > 0 && !dropPending) {
          uint8_t *newBuf = (uint8_t *)safeMalloc(remaining, "DEFER_REM_FLUSH");
          if (newBuf) {
            memcpy(newBuf, chunkPtr + sentTotal, remaining);
            SAFE_FREE(ch.deferredToRemote);
            ch.deferredToRemote = newBuf;
            ch.deferredToRemoteSize = remaining;
            ch.deferredToRemoteOffset = 0;
            LOGF_W("SSH",
                   "Channel %d: Deferred %zu bytes during flush (Local->SSH)",
                   channelIndex, remaining);
          } else {
            dropPending = true;
            dropReason = "alloc failure while deferring";
            dropCode = ENOMEM;
          }
        }

        ch.localToSshBuffer->release(chunkPtr);
        // Ring buffer no longer holds this chunk
        ch.queuedBytesToRemote = (ch.queuedBytesToRemote > chunkSize)
                                     ? ch.queuedBytesToRemote - chunkSize
                                     : 0;
      }

      if (dropPending) {
        size_t droppedBytesLocal = 0;
        if (ch.localToSshBuffer) {
          droppedBytesLocal += ch.localToSshBuffer->size();
          ch.localToSshBuffer->clear();
          ch.queuedBytesToRemote = 0;
        }
        if (ch.deferredToRemote) {
          size_t remain =
              (ch.deferredToRemoteSize > ch.deferredToRemoteOffset)
                  ? (ch.deferredToRemoteSize - ch.deferredToRemoteOffset)
                  : 0;
          droppedBytesLocal += remain;
          SAFE_FREE(ch.deferredToRemote);
          ch.deferredToRemote = nullptr;
          ch.deferredToRemoteSize = 0;
          ch.deferredToRemoteOffset = 0;
        }
        const char *reason =
            dropReason.length() ? dropReason.c_str() : "ssh write failure";
        if (droppedBytesLocal > 0) {
          ch.bytesDropped += droppedBytesLocal;
          if (lockStats()) {
            droppedBytes += droppedBytesLocal;
            unlockStats();
          }
          LOGF_W("SSH", "Channel %d: Dropped %zu bytes pending to remote (%s)",
                 channelIndex, droppedBytesLocal, reason);
          char dropMsg[160];
          snprintf(dropMsg, sizeof(dropMsg), "dropped %zu bytes to remote (%s)",
                   droppedBytesLocal, reason);
          emitChannelError(channelIndex, TunnelErrorCode::DropLocalToSsh,
                           dropCode, dropMsg);
          if (writeBroken) {
            TunnelErrorCode brokenCode = dropCode
                                             ? mapSshErrorToCode(dropCode, true)
                                             : TunnelErrorCode::SshWriteFailure;
            emitChannelWriteBroken(channelIndex, brokenCode, dropCode, dropMsg);
          }
        } else if (writeBroken) {
          TunnelErrorCode brokenCode = dropCode
                                           ? mapSshErrorToCode(dropCode, true)
                                           : TunnelErrorCode::SshWriteFailure;
          char brokenMsg[160];
          snprintf(brokenMsg, sizeof(brokenMsg), "write broken (%s)", reason);
          emitChannelWriteBroken(channelIndex, brokenCode, dropCode, brokenMsg);
        }
        ch.gracefulClosing = true;
        ch.remoteEof = true;
        if (ch.localSocket >= 0) {
          shutdown(ch.localSocket, SHUT_RDWR);
        }
      }
      unlockChannelWrite(channelIndex);
    }
  }
}

bool SSHTunnel::isChannelHealthy(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  // If the channel is marked terminal after a -43 burst, it's immediately
  // unhealthy
  if (ch.terminalSocketFailure) {
    // Switch to DEBUG to avoid repeated WARN spam
    static std::vector<unsigned long> lastTermLog;
    unsigned long now = millis();
    int needed =
        std::max(config->getConnectionConfig().maxChannels, channelIndex + 1);
    if ((int)lastTermLog.size() < needed) {
      lastTermLog.assign(needed, 0);
    }
    if (channelIndex < (int)lastTermLog.size()) {
      if (now - lastTermLog[channelIndex] > 3000) {
        lastTermLog[channelIndex] = now;
        LOGF_W("SSH",
               "Channel %d: Unhealthy (terminal -43 burst) queuedL=%zu "
               "queuedR=%zu",
               channelIndex, ch.queuedBytesToLocal, ch.queuedBytesToRemote);
      } else {
        LOGF_D("SSH", "Channel %d: Terminal burst pending close", channelIndex);
      }
    }
    return false;
  }
  if (!ch.active) {
    return false;
  }

  unsigned long now = millis();
  unsigned long lastProgress = ch.lastSuccessfulWrite;
  if (ch.lastSuccessfulRead > lastProgress) {
    lastProgress = ch.lastSuccessfulRead;
  }
  unsigned long elapsedSinceProgress =
      (lastProgress != 0) ? (now - lastProgress) : (now - ch.lastActivity);
  bool progressStalled = elapsedSinceProgress > kBufferOverloadStallMs;

  // Fatal crypto error -> immediately unhealthy
  if (ch.fatalCryptoErrors > 0) {
    LOGF_D("SSH", "Channel %d: Unhealthy (fatal crypto errors=%d)",
           channelIndex, ch.fatalCryptoErrors);
    return false;
  }
  // Socket recv errors escalation
  if (ch.socketRecvErrors > 4) {
    LOGF_D("SSH", "Channel %d: Unhealthy (socketRecvErrors=%d)", channelIndex,
           ch.socketRecvErrors);
    return false;
  }
  // Check consecutive errors
  if (ch.consecutiveErrors > 3) {
    LOGF_D("SSH", "Channel %d: Unhealthy due to %d consecutive errors",
           channelIndex, ch.consecutiveErrors);
    return false;
  }

  // Check last activity (reduced from 5 minutes to 2 minutes)
  if (now - ch.lastActivity > 120000) { // 2 minutes
    LOGF_D("SSH", "Channel %d: Unhealthy due to inactivity (%lums)",
           channelIndex, now - ch.lastActivity);
    return false;
  }

  // Check unified buffers are not too full (dynamic threshold 95% of capacity)
  if (ch.sshToLocalBuffer) {
    size_t cap = ch.sshToLocalBuffer->capacityBytes();
    size_t limit = cap ? (cap * 95) / 100 : (size_t)(60 * 1024);
    if (limit == 0)
      limit = 1; // safety guard
    if (ch.sshToLocalBuffer->size() > limit && progressStalled) {
      LOGF_D("SSH",
             "Channel %d: Unhealthy due to SSH->Local buffer size (%zu/%zu)",
             channelIndex, ch.sshToLocalBuffer->size(), cap);
      return false;
    }
  }
  if (ch.localToSshBuffer) {
    size_t cap = ch.localToSshBuffer->capacityBytes();
    size_t limit = cap ? (cap * 95) / 100 : (size_t)(60 * 1024);
    if (limit == 0)
      limit = 1; // safety guard
    if (ch.localToSshBuffer->size() > limit && progressStalled) {
      LOGF_D("SSH",
             "Channel %d: Unhealthy due to Local->SSH buffer size (%zu/%zu)",
             channelIndex, ch.localToSshBuffer->size(), cap);
      return false;
    }
  }

  if (ch.queuedBytesToLocal + ch.queuedBytesToRemote > MAX_QUEUED_BYTES) {
    LOGF_D("SSH",
           "Channel %d: Unhealthy due to excessive queued bytes (%zu total)",
           channelIndex, ch.queuedBytesToLocal + ch.queuedBytesToRemote);
    return false;
  }

  //   Check mutex state
  if (ch.readMutex) {
    if (xSemaphoreTake(ch.readMutex, 0) == pdTRUE) {
      xSemaphoreGive(ch.readMutex);
      if (ch.readProbeFailCount) {
        ch.readProbeFailCount = 0;
      }
    } else {
      ch.readProbeFailCount++;
      if (ch.readProbeFailCount >= STUCK_PROBE_THRESHOLD) {
        if (now - ch.lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
          ch.lastHealthWarnMs = now;
          LOGF_W("SSH", "Channel %d: Read mutex blocked (%d probes)",
                 channelIndex, ch.readProbeFailCount);
        }
        return false;
      }
      if ((ch.readProbeFailCount % 3) == 1) {
        LOGF_D("SSH", "Channel %d: Read mutex busy (probe=%d)", channelIndex,
               ch.readProbeFailCount);
      }
    }
  }

  if (ch.writeMutex) {
    if (xSemaphoreTake(ch.writeMutex, 0) == pdTRUE) {
      xSemaphoreGive(ch.writeMutex);
      if (ch.writeProbeFailCount) {
        ch.writeProbeFailCount = 0;
      }
    } else {
      ch.writeProbeFailCount++;
      if (ch.writeProbeFailCount >= STUCK_PROBE_THRESHOLD) {
        if (now - ch.lastHealthWarnMs > HEALTH_WARN_THROTTLE_MS) {
          ch.lastHealthWarnMs = now;
          LOGF_W("SSH", "Channel %d: Write mutex blocked (%d probes)",
                 channelIndex, ch.writeProbeFailCount);
        }
        return false;
      }
      if ((ch.writeProbeFailCount % 3) == 1) {
        LOGF_D("SSH", "Channel %d: Write mutex busy (probe=%d)", channelIndex,
               ch.writeProbeFailCount);
      }
    }
  }

  return true;
}

void SSHTunnel::recoverChannel(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];

  //   Try a graceful recovery first
  if (ch.consecutiveErrors < 5) {
    LOGF_I("SSH", "Channel %d: Attempting graceful recovery (errors: %d)",
           channelIndex, ch.consecutiveErrors);
    gracefulRecoverChannel(channelIndex);
    return;
  }

  // If graceful recovery failed too many times, force a hard recovery
  LOGF_W("SSH", "Channel %d: Too many errors (%d), forcing hard recovery",
         channelIndex, ch.consecutiveErrors);

  //   Force release of stuck mutexes
  if (ch.readMutex) {
    // Check if mutex is stuck by trying to acquire quickly
    if (xSemaphoreTake(ch.readMutex, 0) == pdTRUE) {
      xSemaphoreGive(ch.readMutex); // It was free; release back
    } else {
      // Mutex appears stuck; recreate it
      LOGF_W("SSH", "Channel %d: Read mutex appears stuck, recreating",
             channelIndex);
      vSemaphoreDelete(ch.readMutex);
      ch.readMutex = xSemaphoreCreateMutex();
      if (!ch.readMutex) {
        LOGF_E("SSH", "Channel %d: Failed to recreate read mutex",
               channelIndex);
      }
    }
  }

  if (ch.writeMutex) {
    if (xSemaphoreTake(ch.writeMutex, 0) == pdTRUE) {
      xSemaphoreGive(ch.writeMutex); // It was free; release back
    } else {
      // Mutex appears stuck; recreate it
      LOGF_W("SSH", "Channel %d: Write mutex appears stuck, recreating",
             channelIndex);
      vSemaphoreDelete(ch.writeMutex);
      ch.writeMutex = xSemaphoreCreateMutex();
      if (!ch.writeMutex) {
        LOGF_E("SSH", "Channel %d: Failed to recreate write mutex",
               channelIndex);
      }
    }
  }

  //   Only now flush pending data in a hard recovery scenario
  flushPendingData(channelIndex);

  // Reset error counters
  ch.consecutiveErrors = 0;
  ch.eagainErrors = 0;
  ch.flowControlPaused = false;
  ch.localReadPaused = false;
  ch.pendingBytes = 0;

  // Check state of sockets/channels
  if (ch.localSocket >= 0) {
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(ch.localSocket, SOL_SOCKET, SO_ERROR, &error, &len) != 0 ||
        error != 0) {
      LOGF_W("SSH", "Channel %d: Local socket error during recovery, closing",
             channelIndex);
      closeChannel(channelIndex);
      return;
    }
  }

  if (ch.channel && channelEofLocked(ch.channel)) {
    LOGF_W("SSH", "Channel %d: SSH channel EOF during recovery, closing",
           channelIndex);
    closeChannel(channelIndex);
    return;
  }

  ch.localReadTerminated = false;
  ch.lastActivity = millis();
  LOGF_I("SSH", "Channel %d: Hard recovery completed", channelIndex);
}

size_t SSHTunnel::getOptimalBufferSize(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  const size_t MIN_BUFFER_SIZE = 1024; // Never below this
  const size_t MAX_BUFFER_SIZE = 1460; // Typical Ethernet MTU
  size_t baseSize = config->getConnectionConfig().bufferSize;
  if (baseSize < MIN_BUFFER_SIZE)
    baseSize = MIN_BUFFER_SIZE;
  if (baseSize > MAX_BUFFER_SIZE)
    baseSize = MAX_BUFFER_SIZE;

  // If persistent errors, remain at the safe minimum size
  if (ch.consecutiveErrors > 5) {
    return MIN_BUFFER_SIZE;
  }

  // For a stable large transfer we can slightly increase (up to MTU)
  if (ch.largeTransferInProgress && ch.consecutiveErrors == 0) {
    size_t boosted = (size_t)(baseSize * 1.2f);
    if (boosted > MAX_BUFFER_SIZE)
      boosted = MAX_BUFFER_SIZE;
    return boosted;
  }
  return baseSize;
}

bool SSHTunnel::isSocketReadable(int sockfd, int timeoutMs) {
  if (sockfd < 0)
    return false;

  // First check socket state with getsockopt
  int sockError = 0;
  socklen_t errLen = sizeof(sockError);
  if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sockError, &errLen) == 0 &&
      sockError != 0) {
    LOGF_D("SSH", "Socket %d error in isSocketReadable: %s", sockfd,
           strerror(sockError));
    return false;
  }

  fd_set rfds, errfds;
  FD_ZERO(&rfds);
  FD_ZERO(&errfds);
  FD_SET(sockfd, &rfds);
  FD_SET(sockfd, &errfds); // Also monitor errors

  struct timeval tv;
  tv.tv_sec = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;

  int r = lwip_select(sockfd + 1, &rfds, nullptr, &errfds,
                      (timeoutMs >= 0 ? &tv : nullptr));
  if (r <= 0)
    return false;

  // Check if there's an error on the socket
  if (FD_ISSET(sockfd, &errfds)) {
    LOGF_D("SSH", "Socket %d error detected in select", sockfd);
    return false;
  }

  return FD_ISSET(sockfd, &rfds);
}

bool SSHTunnel::isSocketWritable(int sockfd, int timeoutMs) {
  if (sockfd < 0)
    return false;

  // First check socket state
  int sockError = 0;
  socklen_t errLen = sizeof(sockError);
  if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sockError, &errLen) == 0 &&
      sockError != 0) {
    LOGF_D("SSH", "Socket %d error in isSocketWritable: %s", sockfd,
           strerror(sockError));
    return false;
  }

  fd_set wfds, errfds;
  FD_ZERO(&wfds);
  FD_ZERO(&errfds);
  FD_SET(sockfd, &wfds);
  FD_SET(sockfd, &errfds);

  struct timeval tv;
  tv.tv_sec = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;

  int r = lwip_select(sockfd + 1, nullptr, &wfds, &errfds,
                      (timeoutMs >= 0 ? &tv : nullptr));
  if (r <= 0)
    return false;

  if (FD_ISSET(sockfd, &errfds)) {
    LOGF_D("SSH", "Socket %d error detected in writable select", sockfd);
    return false;
  }

  return FD_ISSET(sockfd, &wfds);
}

//   Method to detect and recover deadlocks
void SSHTunnel::checkAndRecoverDeadlocks() {
  if (!channels)
    return;

  unsigned long now = millis();
  int maxChannels = config->getConnectionConfig().maxChannels;
  static std::vector<unsigned long> lastChannelActivity;
  static unsigned long allStuckSinceMs = 0;
  static unsigned long lastGlobalResetMs = 0;
  int activeCount = 0;
  int stuckPendingCount = 0;
  if ((int)lastChannelActivity.size() < maxChannels) {
    lastChannelActivity.assign(maxChannels, 0);
  }

  for (int i = 0; i < maxChannels; i++) {
    TunnelChannel &ch = channels[i];
    if (!ch.active)
      continue;

    activeCount++;

    size_t pendingToRemote = getPendingToRemoteBytes(ch);
    size_t pendingBytes = ch.queuedBytesToLocal + ch.queuedBytesToRemote;
    if (ch.sshToLocalBuffer) {
      pendingBytes += ch.sshToLocalBuffer->size();
    }
    if (ch.localToSshBuffer) {
      pendingBytes += ch.localToSshBuffer->size();
    }
    if (ch.deferredToLocal &&
        ch.deferredToLocalOffset < ch.deferredToLocalSize) {
      pendingBytes += ch.deferredToLocalSize - ch.deferredToLocalOffset;
    }
    if (ch.deferredToRemote &&
        ch.deferredToRemoteOffset < ch.deferredToRemoteSize) {
      pendingBytes += ch.deferredToRemoteSize - ch.deferredToRemoteOffset;
    }

    // Check if the channel is "stuck" (no activity for 30 seconds)
    bool channelStuck = (now - ch.lastActivity) > 30000;
    bool stuckWithPending = channelStuck && pendingBytes > 0;
    if (stuckWithPending) {
      stuckPendingCount++;
    }
    unsigned long lastProgress = ch.lastSuccessfulWrite;
    if (ch.lastSuccessfulRead > lastProgress) {
      lastProgress = ch.lastSuccessfulRead;
    }
    bool progressStalled = false;
    if (lastProgress != 0 && now >= lastProgress) {
      progressStalled = (now - lastProgress) > kBufferOverloadStallMs;
    } else {
      progressStalled = channelStuck;
    }

    // Check stuck mutexes using a quick non-blocking acquisition
    bool readMutexStuck = false, writeMutexStuck = false;

    if (ch.readMutex) {
      if (xSemaphoreTake(ch.readMutex, 0) == pdTRUE) {
        xSemaphoreGive(ch.readMutex); // Was free
      } else {
        readMutexStuck = true;
      }
    }

    if (ch.writeMutex) {
      if (xSemaphoreTake(ch.writeMutex, 0) == pdTRUE) {
        xSemaphoreGive(ch.writeMutex); // Was free
      } else {
        writeMutexStuck = true;
      }
    }

    // Detect a likely deadlock
    bool deadlockDetected = channelStuck && (readMutexStuck || writeMutexStuck);

    // Check if unified buffers are abnormally full
    bool buffersOverloaded = false;
    if (ch.sshToLocalBuffer) {
      size_t cap = ch.sshToLocalBuffer->capacityBytes();
      size_t limit = cap ? (cap * 95) / 100 : (size_t)(60 * 1024);
      if (ch.sshToLocalBuffer->size() > limit && progressStalled) {
        buffersOverloaded = true;
      }
    }
    if (ch.localToSshBuffer) {
      size_t cap = ch.localToSshBuffer->capacityBytes();
      size_t limit = cap ? (cap * 95) / 100 : (size_t)(60 * 1024);
      size_t pendingLocalToRemote =
          std::max(ch.localToSshBuffer->size(), pendingToRemote);
      if (pendingLocalToRemote > limit && progressStalled) {
        buffersOverloaded = true;
      }
    }

    if (deadlockDetected || buffersOverloaded) {
      LOGF_W("SSH",
             "Channel %d: Deadlock detected (stuck=%s, rMutex=%s, wMutex=%s, "
             "bufOverload=%s) - triggering recovery",
             i, channelStuck ? "YES" : "NO", readMutexStuck ? "STUCK" : "OK",
             writeMutexStuck ? "STUCK" : "OK",
             buffersOverloaded ? "YES" : "NO");

      recoverChannel(i);
      if (i < (int)lastChannelActivity.size()) {
        lastChannelActivity[i] = now; // Reset timer
      }
    } else if (i < (int)lastChannelActivity.size()) {
      // Update normal activity timer
      if (ch.lastActivity > lastChannelActivity[i]) {
        lastChannelActivity[i] = ch.lastActivity;
      }
    }
  }

  if (activeCount > 0 && stuckPendingCount == activeCount) {
    if (allStuckSinceMs == 0) {
      allStuckSinceMs = now;
    }
    if (!sessionResetTriggered &&
        (now - allStuckSinceMs) > kGlobalStallResetMs &&
        (now - lastGlobalResetMs) > kGlobalStallResetCooldownMs) {
      lastGlobalResetMs = now;
      allStuckSinceMs = now;
      sessionResetTriggered = true;
      LOGF_W("SSH",
             "Global stall detected (active=%d pendingStuck=%d) -> "
             "scheduling session reset",
             activeCount, stuckPendingCount);
    }
  } else {
    allStuckSinceMs = 0;
  }
}
//   Detailed data transfer diagnostics
void SSHTunnel::printDataTransferStats(int channelIndex) {
  if (!channels || channelIndex < 0 ||
      channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }

  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active)
    return;

  size_t sshToLocalSize = ch.sshToLocalBuffer ? ch.sshToLocalBuffer->size() : 0;
  size_t localToSshSize = ch.localToSshBuffer ? ch.localToSshBuffer->size() : 0;

  LOGF_I("SSH", "Channel %d Transfer Stats:", channelIndex);
  LOGF_I("SSH", "  - Total RX: %zu bytes, TX: %zu bytes", ch.totalBytesReceived,
         ch.totalBytesSent);
  LOGF_I("SSH", "  - Queued to Local: %zu, to Remote: %zu",
         ch.queuedBytesToLocal, ch.queuedBytesToRemote);
  LOGF_I("SSH", "  - Buffers: SSH->Local=%zu bytes, Local->SSH=%zu bytes",
         sshToLocalSize, localToSshSize);
  LOGF_I("SSH",
         "  - Lost chunks: %d, Dropped bytes: %zu, Consecutive errors: %d, "
         "EAGAIN errors: %d",
         ch.lostWriteChunks, ch.bytesDropped, ch.consecutiveErrors,
         ch.eagainErrors);

  // Calculate buffer utilization ratio
  size_t totalQueued = ch.queuedBytesToLocal + ch.queuedBytesToRemote;
  size_t totalBuffered = sshToLocalSize + localToSshSize;
  size_t totalTransferred = ch.totalBytesReceived + ch.totalBytesSent;

  if (totalTransferred > 0) {
    float bufferRatio =
        (float)(totalQueued + totalBuffered) / totalTransferred * 100.0f;
    LOGF_I("SSH", "  - Buffer/Transfer ratio: %.1f%% %s", bufferRatio,
           bufferRatio > 50.0f ? "(WARNING: High buffer usage!)" : "");
  }
}

// ====== NEW METHODS FOR LARGE TRANSFER MANAGEMENT ======

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
  if (!ch.active)
    return;

  unsigned long now = millis();
  unsigned long transferDuration = now - ch.transferStartTime;

  // FIX: Compute throughput more conservatively
  if (transferDuration > 2000) { // At least 2 seconds to avoid false positives
    size_t totalTransferred = ch.totalBytesReceived + ch.totalBytesSent;
    size_t currentRate = totalTransferred * 1000 / transferDuration;

    if (currentRate > ch.peakBytesPerSecond) {
      ch.peakBytesPerSecond = currentRate;
    }

    // FIX: Stricter criteria to avoid false positives
    bool wasLargeTransfer = ch.largeTransferInProgress;

    ch.largeTransferInProgress =
        (totalTransferred > LARGE_TRANSFER_THRESHOLD &&
         currentRate > LARGE_TRANSFER_RATE_THRESHOLD &&
         transferDuration > LARGE_TRANSFER_TIME_THRESHOLD &&
         ((ch.sshToLocalBuffer && ch.sshToLocalBuffer->size() > 10 * 1024) ||
          (ch.localToSshBuffer &&
           ch.localToSshBuffer->size() > 10 * 1024)) // Buffer activity (>10KB)
        );

    // Log only on state changes
    if (ch.largeTransferInProgress && !wasLargeTransfer) {
      LOGF_I("SSH",
             "Channel %d: Large transfer detected - Rate: %zu B/s, Total: %zu "
             "bytes",
             channelIndex, currentRate, totalTransferred);
      emitLargeTransferEvent(channelIndex, true);
    } else if (!ch.largeTransferInProgress && wasLargeTransfer) {
      LOGF_I("SSH",
             "Channel %d: Large transfer completed - Peak: %zu B/s, Total: %zu "
             "bytes",
             channelIndex, ch.peakBytesPerSecond, totalTransferred);
      emitLargeTransferEvent(channelIndex, false);
    }
  }
}

bool SSHTunnel::shouldAcceptNewConnection() {
  int activeChannels = getActiveChannels();
  int maxChannels = config->getConnectionConfig().maxChannels;
  if (activeChannels >= maxChannels)
    return false;

  // Reject if a large transfer is active on any channel
  if (isLargeTransferActive()) {
    return false;
  }

  // Reject if an existing channel is overloaded or unstable
  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active) {
      if (channels[i].queuedBytesToRemote > (getHighWaterLocal() + 512)) {
        LOGF_D("SSH", "Reject new conn: channel %d backlog %zu", i,
               channels[i].queuedBytesToRemote);
        return false;
      }
      if (channels[i].consecutiveErrors > 2) {
        LOGF_D("SSH", "Reject new conn: channel %d errors %d", i,
               channels[i].consecutiveErrors);
        return false;
      }
    }
  }

  // Proactively start rejecting around 70% utilization
  if (activeChannels >= (int)(0.7f * maxChannels)) {
    // Still allow if there is no severe backlog
    return true;
  }
  return true;
}

void SSHTunnel::queuePendingConnection(LIBSSH2_CHANNEL *channel,
                                       const TunnelConfig &mapping) {
  if (!channel)
    return;

  // Protect access to the pending queue
  if (xSemaphoreTake(pendingConnectionsMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    // Limit pending queue size
    const size_t MAX_PENDING = 5;

    if (pendingConnections.size() >= MAX_PENDING) {
      // Close the oldest pending connection
      PendingConnection &oldest = pendingConnections.front();
      LOGF_W("SSH",
             "Pending connections queue full - closing oldest connection");

      closeLibssh2Channel(oldest.channel);
      pendingConnections.erase(pendingConnections.begin());
    }

    // Add the new connection
    PendingConnection pending;
    pending.channel = channel;
    pending.timestamp = millis();
    pending.mapping = mapping;
    pendingConnections.push_back(pending);

    LOGF_I("SSH", "Connection queued - %zu connections waiting",
           pendingConnections.size());

    xSemaphoreGive(pendingConnectionsMutex);
  } else {
    // Could not acquire mutex - close connection
    LOGF_E(
        "SSH",
        "Could not acquire mutex for pending connections - closing connection");
    closeLibssh2Channel(channel);
  }
}

bool SSHTunnel::processPendingConnections() {
  if (pendingConnections.empty())
    return false;

  if (xSemaphoreTake(pendingConnectionsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
    unsigned long now = millis();
    const unsigned long MAX_WAIT_TIME = 30000; // 30s max wait time

    for (auto it = pendingConnections.begin();
         it != pendingConnections.end();) {
      // Check if the pending connection expired
      if (now - it->timestamp > MAX_WAIT_TIME) {
        LOGF_W("SSH", "Pending connection expired - closing");
        closeLibssh2Channel(it->channel);
        it = pendingConnections.erase(it);
        continue;
      }

      // Try to process this pending connection
      if (shouldAcceptNewConnection()) {
        LIBSSH2_CHANNEL *channel = it->channel;
        TunnelConfig mapping = it->mapping;
        LOGF_I("SSH", "Processing pending connection - %zu remaining",
               pendingConnections.size() - 1);

        // Remove from queue before processing
        it = pendingConnections.erase(it);

        // Release mutex temporarily to process the connection
        xSemaphoreGive(pendingConnectionsMutex);

        // Process the connection (same logic as handleNewConnection subset)
        if (!processQueuedConnection(channel, mapping)) {
          // On failure, close the connection
          closeLibssh2Channel(channel);
        }

        return true; // One connection processed
      } else {
        ++it; // Move to next
      }
    }

    xSemaphoreGive(pendingConnectionsMutex);
  }

  return false;
}

bool SSHTunnel::processQueuedConnection(LIBSSH2_CHANNEL *channel,
                                        const TunnelConfig &mapping) {
  return bindChannelToMapping(channel, mapping);
}

// ====== NEW OPTIMIZED METHODS ======

//   Dedicated task for data processing (producer/consumer pattern)
void SSHTunnel::dataProcessingTaskWrapper(void *parameter) {
  SSHTunnel *tunnel = static_cast<SSHTunnel *>(parameter);
  tunnel->dataProcessingTaskFunction();
}

void SSHTunnel::dataProcessingTaskFunction() {
  while (dataProcessingTaskRunning) {
    // Wait for work signal or longer timeout to reduce contention
    if (xSemaphoreTake(dataProcessingSemaphore, pdMS_TO_TICKS(200)) ==
        pdTRUE) { // 200ms instead of 100ms
      if (!dataProcessingTaskRunning)
        break;

      int maxChannels = config->getConnectionConfig().maxChannels;
      static unsigned long lastMutexProbe = 0;
      bool doProbe = (millis() - lastMutexProbe) > 3000; // every 3s
      if (doProbe)
        lastMutexProbe = millis();

      std::vector<ChannelScheduleEntry> lowBucket;
      std::vector<ChannelScheduleEntry> normalBucket;
      std::vector<ChannelScheduleEntry> highBucket;
      lowBucket.reserve(maxChannels);
      normalBucket.reserve(maxChannels);
      highBucket.reserve(maxChannels);

      bool hasWorkSignal = false;
      prepareChannelSchedule(lowBucket, normalBucket, highBucket, true,
                             hasWorkSignal);
      (void)hasWorkSignal;

      auto processBucket =
          [&](const std::vector<ChannelScheduleEntry> &bucket) {
            if (bucket.empty()) {
              return;
            }

            uint8_t maxWeight = 0;
            for (const auto &entry : bucket) {
              if (entry.weight > maxWeight) {
                maxWeight = entry.weight;
              }
            }

            for (uint8_t pass = 0; pass < maxWeight; ++pass) {
              for (const auto &entry : bucket) {
                if (pass >= entry.weight) {
                  continue;
                }

                int idx = entry.index;
                if (idx < 0 || idx >= maxChannels) {
                  continue;
                }
                if (!channels[idx].active) {
                  continue;
                }

                if (pass > 0 && !channelHasPendingWork(channels[idx])) {
                  continue;
                }

                processPendingData(idx);
              }
            }
          };

      processBucket(highBucket);
      processBucket(normalBucket);
      processBucket(lowBucket);

      if (doProbe) {
        for (int i = 0; i < maxChannels; ++i) {
          if (channels[i].active && !channels[i].gracefulClosing) {
            safeRetryMutexAccess(i);
          }
        }
      }

      static unsigned long lastLargeTransferCheck = 0;
      if (millis() - lastLargeTransferCheck >
          5000) { // Every 5s instead of each loop
        for (int i = 0; i < maxChannels; ++i) {
          if (channels[i].active) {
            detectLargeTransfer(i);
          }
        }
        lastLargeTransferCheck = millis();
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
    return true; // Already started
  }

  dataProcessingTaskRunning = true;
  uint16_t stackSize = getDataTaskStackSize();
  int8_t coreAffinity = getDataTaskCoreAffinity();
  BaseType_t result;

  if (coreAffinity >= 0) {
    result = xTaskCreatePinnedToCore(
        dataProcessingTaskWrapper, "SSH_DataProcessing", stackSize, this,
        tskIDLE_PRIORITY + 1, &dataProcessingTask, coreAffinity);
  } else {
    result =
        xTaskCreate(dataProcessingTaskWrapper, "SSH_DataProcessing", stackSize,
                    this, tskIDLE_PRIORITY + 1, &dataProcessingTask);
  }

  if (result != pdPASS) {
    LOG_E("SSH", "Failed to create data processing task");
    dataProcessingTaskRunning = false;
    return false;
  }

  LOGF_I("SSH", "Data processing task started (stack=%u, core=%d)", stackSize,
         coreAffinity);
  return true;
}

void SSHTunnel::stopDataProcessingTask() {
  if (dataProcessingTask == nullptr) {
    return; // Not started
  }

  dataProcessingTaskRunning = false;

  // Signal task to exit
  if (dataProcessingSemaphore) {
    xSemaphoreGive(dataProcessingSemaphore);
  }

  // Wait for task termination (1 second timeout)
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

//   Graceful recovery without clearing buffers
void SSHTunnel::gracefulRecoverChannel(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (ch.terminalSocketFailure) {
    LOGF_D("SSH", "Channel %d: Skip graceful recovery (terminal failure)",
           channelIndex);
    return;
  }

  LOGF_I("SSH", "Channel %d: Attempting graceful recovery", channelIndex);

  // 1. Check socket/channel state without immediately closing
  bool localSocketOk = (ch.localSocket >= 0);
  bool sshChannelOk = (ch.channel != nullptr && !channelEofLocked(ch.channel));

  if (localSocketOk) {
    int sockError = 0;
    socklen_t errLen = sizeof(sockError);
    if (getsockopt(ch.localSocket, SOL_SOCKET, SO_ERROR, &sockError, &errLen) ==
            0 &&
        sockError != 0) {
      localSocketOk = false;
      LOGF_I("SSH", "Channel %d: Local socket has error: %s", channelIndex,
             strerror(sockError));
    }
  }

  // 2. Try flushing remaining data if at least one side still works
  if (localSocketOk || sshChannelOk) {
    LOGF_I("SSH",
           "Channel %d: Attempting to flush remaining data (local=%d, ssh=%d)",
           channelIndex, localSocketOk, sshChannelOk);

    // Attempt to flush buffers multiple times
    for (int retry = 0; retry < 5; retry++) {
      size_t localBytes = ch.sshToLocalBuffer ? ch.sshToLocalBuffer->size() : 0;
      size_t sshBytes = ch.localToSshBuffer ? ch.localToSshBuffer->size() : 0;

      if (localBytes == 0 && sshBytes == 0) {
        LOGF_I("SSH", "Channel %d: All data flushed successfully",
               channelIndex);
        break;
      }

      // Try processing remaining data
      processPendingData(channelIndex);

      vTaskDelay(pdMS_TO_TICKS(100)); // Wait 100ms between attempts
    }
  }

  // 3. Partial reset of error counters to give a chance
  if (ch.consecutiveErrors > 0) {
    ch.consecutiveErrors =
        ch.consecutiveErrors / 2; // Halve instead of full reset
    LOGF_I("SSH", "Channel %d: Reduced consecutive errors to %d", channelIndex,
           ch.consecutiveErrors);
  }

  ch.eagainErrors = 0; // Reset EAGAIN errors
  ch.flowControlPaused = false;
  ch.localReadPaused = false;

  // 4. Update activity timestamp
  ch.lastActivity = millis();

  LOGF_I("SSH", "Channel %d: Graceful recovery completed", channelIndex);
}
