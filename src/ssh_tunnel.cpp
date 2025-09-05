#include "ssh_tunnel.h"
#include "network_optimizations.h"
#include "memory_fixes.h"
#include "lwip/sockets.h"
SSHTunnel::SSHTunnel()
    : session(nullptr), listener(nullptr), socketfd(-1),
      state(TUNNEL_DISCONNECTED), lastKeepAlive(0), lastConnectionAttempt(0),
      reconnectAttempts(0), bytesReceived(0), bytesSent(0),
      channels(nullptr), rxBuffer(nullptr), txBuffer(nullptr),
      tunnelMutex(nullptr), statsMutex(nullptr), config(&globalSSHConfig) {

  // Créer les sémaphores de protection
  tunnelMutex = xSemaphoreCreateMutex();
  statsMutex = xSemaphoreCreateMutex();
  
  if (tunnelMutex == NULL || statsMutex == NULL) {
    LOG_E("SSH", "Failed to create tunnel mutexes");
  }
}

SSHTunnel::~SSHTunnel() {
  disconnect();
  
  // Libérer les sémaphores
  SAFE_DELETE_SEMAPHORE(tunnelMutex);
  SAFE_DELETE_SEMAPHORE(statsMutex);
  
  // Libérer la mémoire allouée dynamiquement
  if (channels != nullptr) {
    for (int i = 0; i < config->getConnectionConfig().maxChannels; i++) {
      // Vider les queues de données en attente
      while (!channels[i].pendingWriteQueue.empty()) {
        PendingData data = channels[i].pendingWriteQueue.front();
        channels[i].pendingWriteQueue.pop();
        if (data.data) {
          SAFE_FREE(data.data);
        }
      }
      while (!channels[i].pendingReadQueue.empty()) {
        PendingData data = channels[i].pendingReadQueue.front();
        channels[i].pendingReadQueue.pop();
        if (data.data) {
          SAFE_FREE(data.data);
        }
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
  
  // Valider la configuration
  if (!config->validateConfiguration()) {
    LOG_E("SSH", "Invalid configuration");
    unlockTunnel();
    return false;
  }
  
  // Allouer la mémoire pour les canaux avec vérification
  int maxChannels = config->getConnectionConfig().maxChannels;
  size_t channelsSize = sizeof(TunnelChannel) * maxChannels;
  channels = (TunnelChannel*)safeMalloc(channelsSize, "SSH_CHANNELS");
  if (channels == nullptr) {
    LOG_E("SSH", "Failed to allocate memory for channels");
    unlockTunnel();
    return false;
  }
  
  // Initialiser les canaux
  for (int i = 0; i < maxChannels; i++) {
    channels[i].channel = nullptr;
    channels[i].localSocket = -1;
    channels[i].active = false;
    channels[i].lastActivity = 0;
    channels[i].pendingBytes = 0;
    channels[i].flowControlPaused = false;
    
    // Initialiser les nouvelles structures pour la fiabilité
    channels[i].totalBytesReceived = 0;
    channels[i].totalBytesSent = 0;
    channels[i].lastSuccessfulWrite = 0;
    channels[i].lastSuccessfulRead = 0;
  channels[i].gracefulClosing = false;
  channels[i].consecutiveErrors = 0;
  channels[i].queuedBytesToLocal = 0;
  channels[i].queuedBytesToRemote = 0;
  channels[i].deferredReadData = nullptr;
  channels[i].deferredReadSize = 0;
  channels[i].deferredReadOffset = 0;
  channels[i].deferredWriteData = nullptr;
  channels[i].deferredWriteSize = 0;
  channels[i].deferredWriteOffset = 0;
  channels[i].lostWriteChunks = 0;
    // Les queues sont initialisées automatiquement par std::queue
    
    // Créer les deux mutex pour chaque canal
    channels[i].readMutex = xSemaphoreCreateMutex();
    channels[i].writeMutex = xSemaphoreCreateMutex();
    
    if (channels[i].readMutex == NULL || channels[i].writeMutex == NULL) {
      LOGF_E("SSH", "Failed to create mutexes for channel %d", i);
      unlockTunnel();
      return false;
    }
  }
  
  // Allouer les buffers avec vérification
  int bufferSize = config->getConnectionConfig().bufferSize;
  rxBuffer = (uint8_t*)safeMalloc(bufferSize, "SSH_RX_BUFFER");
  txBuffer = (uint8_t*)safeMalloc(bufferSize, "SSH_TX_BUFFER");
  
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

  LOG_I("SSH", "SSH tunnel initialized");
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

  // Close all channels avec protection pour éviter NULL pointer
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

  // Print statistics périodiques
  printChannelStatistics();

  // Handle new connections
  handleNewConnection();

  // Handle data for existing channels
  int maxChannels = config->getConnectionConfig().maxChannels;
  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active) {
      handleChannelData(i);
    }
  }

  // Cleanup inactive channels
  cleanupInactiveChannels();
  
  // Utiliser vTaskDelay au lieu de delay pour être plus compatible FreeRTOS
  vTaskDelay(pdMS_TO_TICKS(1));
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
  
  // Si la vérification n'est pas activée, on accepte tout
  if (!sshConfig.verifyHostKey) {
    LOG_W("SSH", "Host key verification disabled - connection accepted without verification");
    return true;
  }
  
  // Obtenir l'empreinte du serveur
  size_t host_key_len;
  int host_key_type;
  const char* host_key = libssh2_session_hostkey(session, &host_key_len, &host_key_type);
  
  if (!host_key) {
    LOG_E("SSH", "Failed to get host key from server");
    return false;
  }
  
  // Obtenir l'empreinte SHA256
  const char *fingerprint_sha256 = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256);
  if (!fingerprint_sha256) {
    LOG_E("SSH", "Failed to get host key fingerprint");
    return false;
  }
  
  // Convertir l'empreinte en hexadécimal
  String currentFingerprint = "";
  for (int i = 0; i < 32; i++) {  // SHA256 = 32 bytes
    char hex[3];
    sprintf(hex, "%02x", (unsigned char)fingerprint_sha256[i]);
    currentFingerprint += hex;
  }
  
  // Vérifier le type de clé si spécifié
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
  
  // Vérifier le type de clé si spécifié
  if (sshConfig.hostKeyType.length() > 0 && sshConfig.hostKeyType != keyTypeStr) {
    LOGF_E("SSH", "Host key type mismatch! Expected: %s, Got: %s", 
           sshConfig.hostKeyType.c_str(), keyTypeStr.c_str());
    return false;
  }
  
  // Vérifier l'empreinte
  if (sshConfig.expectedHostKeyFingerprint.length() == 0) {
    LOG_W("SSH", "No expected fingerprint configured - accepting and storing current fingerprint");
    LOGF_I("SSH", "Store this fingerprint in your configuration: %s", currentFingerprint.c_str());
    return true;
  }
  
  // Normaliser les empreintes (supprimer les espaces, mettre en minuscules)
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
    // Diagnostiquer les clés avant l'authentification
    config->diagnoseSSHKeys();
    
    // Vérifier si nous avons les clés en mémoire
    if (sshConfig.privateKeyData.length() > 0 && sshConfig.publicKeyData.length() > 0) {
      // Valider les clés avant l'authentification
      if (!config->validateSSHKeys()) {
        LOG_E("SSH", "SSH keys validation failed");
        return false;
      }
      
      // Utiliser libssh2_userauth_publickey_frommemory
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
        
        // Tentative avec passphrase vide explicite
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
          
          // Dernière tentative : essayer avec NULL au lieu de chaîne vide
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
            
            // Information sur les formats supportés par libssh2
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
      // Fallback vers la méthode par fichier (pour compatibilité)
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
  
  // Utiliser la configuration au lieu des constantes
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

  // Find available channel slot avec réutilisation agressive
  int channelIndex = -1;
  int maxChannels = config->getConnectionConfig().maxChannels;
  unsigned long now = millis();
  
  // Première passe : chercher un canal vraiment libre
  for (int i = 0; i < maxChannels; i++) {
    LOGF_D("SSH", "Trying to open new channel slot %d (active=%d)", i, channels[i].active);
    if (!channels[i].active) {
      channelIndex = i;
      LOGF_I("SSH", "Channel slot %d is free and will be used", i);
      break;
    }
  }

  // Si aucun canal libre, chercher des canaux "nettoyables" (inactifs depuis longtemps)
  if (channelIndex == -1) {
    for (int i = 0; i < maxChannels; i++) {
      if (channels[i].active && (now - channels[i].lastActivity > 30000)) { // 30 secondes d'inactivité
        LOGF_I("SSH", "Recycling inactive channel %d for new connection", i);
        closeChannel(i); // Ferme et libère le canal
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
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);
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

  // Vérifier la santé du canal avant de traiter les données
  if (!isChannelHealthy(channelIndex)) {
    if (ch.consecutiveErrors > 5) {
      LOGF_W("SSH", "Channel %d: Too many consecutive errors, attempting recovery", channelIndex);
      recoverChannel(channelIndex);
      return;
    }
  }

  // Traiter d'abord les données en attente pour éviter l'accumulation
  processPendingData(channelIndex);

  // SSH -> Local (lecture du canal SSH et écriture vers socket local)
  bool readSuccess = processChannelRead(channelIndex);
  
  // Local -> SSH (lecture du socket local et écriture vers canal SSH)
  bool writeSuccess = processChannelWrite(channelIndex);

  // Mettre à jour l'activité si des données ont été transférées
  if (readSuccess || writeSuccess) {
    ch.lastActivity = now;
    ch.consecutiveErrors = 0; // Reset des erreurs après succès
  }

  // Vérifier si le canal doit être fermé proprement
  if (ch.gracefulClosing && ch.pendingWriteQueue.empty() && ch.pendingReadQueue.empty()) {
    LOGF_I("SSH", "Channel %d: Graceful close completed", channelIndex);
    closeChannel(channelIndex);
  }
}

void SSHTunnel::closeChannel(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active)
    return;

  unsigned long sessionDuration = millis() - ch.lastActivity;
  
  // Log détaillé pour le debugging avec les nouvelles statistiques
  LOGF_I("SSH", "Closing channel %d (session: %lums, rx: %d bytes, tx: %d bytes, errors: %d)", 
         channelIndex, sessionDuration, ch.totalBytesReceived, ch.totalBytesSent, ch.consecutiveErrors);

  // Nettoyer les données en attente avant fermeture
  flushPendingData(channelIndex);

  if (ch.channel) {
    libssh2_channel_close(ch.channel);
    libssh2_channel_free(ch.channel);
    ch.channel = nullptr;
  }

  if (ch.localSocket >= 0) {
    close(ch.localSocket);
    ch.localSocket = -1;
  }

  // Reset complet de l'état du canal pour réutilisation
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
  if (ch.deferredReadData) {
    SAFE_FREE(ch.deferredReadData);
    ch.deferredReadData = nullptr;
  }
  ch.deferredReadSize = 0;
  ch.deferredReadOffset = 0;
  if (ch.deferredWriteData) {
    SAFE_FREE(ch.deferredWriteData);
    ch.deferredWriteData = nullptr;
  }
  ch.deferredWriteSize = 0;
  ch.deferredWriteOffset = 0;
  ch.lostWriteChunks = 0;

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
      
      // Nettoyage intelligent et moins agressif
      bool shouldClose = false;
      
      // Vérifier d'abord si le canal est en fermeture gracieuse
      if (channels[i].gracefulClosing) {
        // Permettre plus de temps pour vider les queues
        if (channels[i].pendingWriteQueue.empty() && channels[i].pendingReadQueue.empty()) {
          shouldClose = true;
          LOGF_I("SSH", "Channel %d graceful close completed", i);
        } else if (timeSinceActivity > 30000) { // 30 secondes max pour graceful close
          shouldClose = true;
          LOGF_W("SSH", "Channel %d graceful close timeout", i);
        }
      } else {
        // Timeout normal mais plus tolérant
        if (timeSinceActivity > channelTimeout * 2) { // Double du timeout normal
          shouldClose = true;
          LOGF_W("SSH", "Channel %d timeout after %lums, closing", i, timeSinceActivity);
        }
        // Canaux avec trop d'erreurs consécutives
        else if (channels[i].consecutiveErrors > 10) {
          shouldClose = true;
          LOGF_W("SSH", "Channel %d has too many errors (%d), closing", i, channels[i].consecutiveErrors);
        }
        // Queues trop pleines depuis trop longtemps
        else if ((channels[i].pendingWriteQueue.size() > 8 || channels[i].pendingReadQueue.size() > 8) && 
                 timeSinceActivity > 60000) {
          shouldClose = true;
          LOGF_W("SSH", "Channel %d has full queues for %lums, closing", i, timeSinceActivity);
        }
        // Données anciennes dans les queues (plus de 10 secondes)
        else if (!channels[i].pendingWriteQueue.empty() || !channels[i].pendingReadQueue.empty()) {
          // Vérifier l'âge des données en queue
          bool hasOldData = false;
          if (!channels[i].pendingWriteQueue.empty()) {
            unsigned long age = now - channels[i].pendingWriteQueue.front().timestamp;
            if (age > 10000) hasOldData = true;
          }
          if (!channels[i].pendingReadQueue.empty()) {
            unsigned long age = now - channels[i].pendingReadQueue.front().timestamp;
            if (age > 10000) hasOldData = true;
          }
          
          if (hasOldData) {
            LOGF_W("SSH", "Channel %d has old queued data, cleaning up", i);
            // Nettoyer les données anciennes plutôt que fermer le canal
            processPendingData(i);
          }
        }
      }
      
      if (shouldClose) {
        closeChannel(i);
      }
    }
  }
  
  // Log périodique de l'état des canaux (toutes les 60 secondes)
  static unsigned long lastLog = 0;
  if (now - lastLog > 60000) {
    int activeAfter = getActiveChannels();
    int totalQueued = 0;
    for (int i = 0; i < maxChannels; i++) {
      if (channels[i].active) {
        totalQueued += channels[i].pendingWriteQueue.size() + channels[i].pendingReadQueue.size();
      }
    }
    LOGF_I("SSH", "Channel status: %d active, %d total queued items", activeAfter, totalQueued);
    lastLog = now;
  }
}

void SSHTunnel::printChannelStatistics() {
  static unsigned long lastStatsTime = 0;
  unsigned long now = millis();
  
  // Print stats toutes les 2 minutes
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
  
  LOGF_I("SSH", "Channel Stats: Active=%d/%d, FlowPaused=%d, TotalPending=%d bytes", 
         activeCount, maxChannels, flowPausedCount, pendingBytesTotal);
  
  // Alertes spéciales
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
// Méthodes de protection par sémaphore
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

// Nouvelles méthodes avec mutex séparés et timeout court
bool SSHTunnel::lockChannelRead(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) {
    return false;
  }
  
  if (channels[channelIndex].readMutex == NULL) {
    return false;
  }
  
  // Timeout court de 50ms pour éviter les blocages
  return xSemaphoreTake(channels[channelIndex].readMutex, pdMS_TO_TICKS(50)) == pdTRUE;
}

void SSHTunnel::unlockChannelRead(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }
  
  if (channels[channelIndex].readMutex != NULL) {
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
  
  // Timeout court de 50ms pour éviter les blocages
  return xSemaphoreTake(channels[channelIndex].writeMutex, pdMS_TO_TICKS(50)) == pdTRUE;
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

// Nouvelles méthodes pour améliorer la fiabilité de transmission

bool SSHTunnel::processChannelRead(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active || !ch.channel || ch.localSocket < 0) {
    return false;
  }

  if (!lockChannelRead(channelIndex)) {
    return false;
  }

  bool success = false;
  size_t bufferSize = getOptimalBufferSize(channelIndex);
  unsigned long now = millis();
  // Nouveau flow control avec high/low watermarks
  static const size_t HIGH_WATER_LOCAL = 24 * 512; // 12KB
  if (ch.flowControlPaused) {
    unlockChannelRead(channelIndex);
    return false; // pause active
  }
  if (ch.queuedBytesToLocal > HIGH_WATER_LOCAL) {
    ch.flowControlPaused = true;
    LOGF_W("SSH", "Channel %d: Flow control PAUSE (queuedToLocal=%d)", channelIndex, (int)ch.queuedBytesToLocal);
    unlockChannelRead(channelIndex);
    return false;
  }

  // Double vérification après acquisition du mutex
  if (ch.active && ch.channel && ch.localSocket >= 0) {
    ssize_t bytesRead = libssh2_channel_read(ch.channel, (char *)rxBuffer, bufferSize);
    
  if (bytesRead > 0) {
      // Tenter d'écrire directement vers le socket local
      ssize_t written = send(ch.localSocket, rxBuffer, bytesRead, MSG_DONTWAIT);
      
      if (written == bytesRead) {
        // Succès complet
        ch.totalBytesReceived += written;
        ch.lastSuccessfulWrite = now;
        if (lockStats()) {
          bytesReceived += written;
          unlockStats();
        }
        success = true;
        LOGF_D("SSH", "Channel %d: SSH->Local %d bytes (direct)", channelIndex, written);
      } else if (written > 0) {
        // Écriture partielle - mettre le reste en queue
        ch.totalBytesReceived += written;
        ch.lastSuccessfulWrite = now;
        if (lockStats()) {
          bytesReceived += written;
          unlockStats();
        }
        
        // Mettre les données restantes en queue
        size_t remaining = bytesRead - written;
        if (queueData(channelIndex, rxBuffer + written, remaining, true)) {
          LOGF_D("SSH", "Channel %d: SSH->Local %d bytes written, %d queued", 
                 channelIndex, written, remaining);
          success = true;
        } else {
          LOGF_E("SSH", "Channel %d: Failed to queue remaining data", channelIndex);
          ch.consecutiveErrors++;
        }
      } else if (written < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // Socket plein - mettre toutes les données en queue
          if (queueData(channelIndex, rxBuffer, bytesRead, true)) {
            LOGF_D("SSH", "Channel %d: SSH->Local %d bytes queued (socket full)", 
                   channelIndex, bytesRead);
            success = true;
          } else {
            LOGF_E("SSH", "Channel %d: Failed to queue data (socket full)", channelIndex);
            ch.consecutiveErrors++;
          }
        } else if (errno == ECONNRESET || errno == EPIPE) {
          LOGF_I("SSH", "Channel %d: Local connection closed during write", channelIndex);
          ch.gracefulClosing = true;
        } else {
          LOGF_W("SSH", "Channel %d: Local write error: %s", channelIndex, strerror(errno));
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

  if (!lockChannelWrite(channelIndex)) {
    return false;
  }

  bool success = false;
  size_t bufferSize = getOptimalBufferSize(channelIndex);
  unsigned long now = millis();

  // Double vérification après acquisition du mutex
  if (ch.active && ch.channel && ch.localSocket >= 0) {
    // Utiliser poll avant chaque tentative de lecture
    if (isSocketReadable(ch.localSocket, 10)) {
      ssize_t bytesRead = recv(ch.localSocket, txBuffer, bufferSize, MSG_DONTWAIT);
      if (bytesRead > 0) {
        // Tenter d'écrire directement vers le canal SSH
        ssize_t written = libssh2_channel_write(ch.channel, (char *)txBuffer, bytesRead);
        if (written == bytesRead) {
          // Succès complet
          ch.totalBytesSent += written;
          ch.lastSuccessfulRead = now;
          if (lockStats()) {
            bytesSent += written;
            unlockStats();
          }
          success = true;
          LOGF_D("SSH", "Channel %d: Local->SSH %d bytes (direct)", channelIndex, written);
        } else if (written > 0) {
          // Écriture partielle - mettre le reste en queue
          ch.totalBytesSent += written;
          ch.lastSuccessfulRead = now;
          if (lockStats()) {
            bytesSent += written;
            unlockStats();
          }
          // Mettre les données restantes en queue
          size_t remaining = bytesRead - written;
          if (queueData(channelIndex, txBuffer + written, remaining, false)) {
            LOGF_D("SSH", "Channel %d: Local->SSH %d bytes written, %d queued", 
                   channelIndex, written, remaining);
            success = true;
          } else {
            LOGF_E("SSH", "Channel %d: Failed to queue remaining data", channelIndex);
            ch.consecutiveErrors++;
          }
        } else if (written < 0) {
          if (written == LIBSSH2_ERROR_EAGAIN) {
            // Canal SSH plein - mettre toutes les données en queue
            if (queueData(channelIndex, txBuffer, bytesRead, false)) {
              LOGF_D("SSH", "Channel %d: Local->SSH %d bytes queued (channel full)", 
                     channelIndex, bytesRead);
              success = true;
            } else {
              LOGF_E("SSH", "Channel %d: Failed to queue data (channel full)", channelIndex);
              ch.consecutiveErrors++;
            }
          } else {
            LOGF_W("SSH", "Channel %d: SSH write error: %d", channelIndex, written);
            ch.consecutiveErrors++;
          }
        }
      } else if (bytesRead == 0) {
        LOGF_I("SSH", "Channel %d: Local socket closed", channelIndex);
        ch.gracefulClosing = true;
      } else if (bytesRead < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
          if (errno == ECONNRESET || errno == EPIPE) {
            LOGF_I("SSH", "Channel %d: Local connection reset", channelIndex);
            ch.gracefulClosing = true;
          } else {
            LOGF_W("SSH", "Channel %d: Local read error: %s", channelIndex, strerror(errno));
            ch.consecutiveErrors++;
          }
        }
      }
    }
    // Vérification stricte sur deferredWriteData
    if (ch.deferredWriteData && ch.deferredWriteSize > ch.deferredWriteOffset) {
      size_t toSend = ch.deferredWriteSize - ch.deferredWriteOffset;
      if (toSend > 0 && ch.deferredWriteData) {
        ssize_t written = libssh2_channel_write(ch.channel, (char*)ch.deferredWriteData + ch.deferredWriteOffset, toSend);
        if (written > 0) {
          ch.deferredWriteOffset += written;
          ch.totalBytesSent += written;
          success = true;
        }
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
  const unsigned long maxAge = 5000; // 5 secondes max pour les données en attente
  // 1) Flusher d'abord le buffer différé (deferredReadData) si présent
  if (ch.deferredReadData && ch.deferredReadSize > ch.deferredReadOffset) {
    if (ch.localSocket >= 0 && isSocketWritable(ch.localSocket, 10)) {
      size_t remaining = ch.deferredReadSize - ch.deferredReadOffset;
      if (remaining > 0 && ch.deferredReadData) {
        ssize_t written = send(ch.localSocket, ch.deferredReadData + ch.deferredReadOffset, remaining, MSG_DONTWAIT);
        if (written > 0) {
          ch.deferredReadOffset += written;
          ch.totalBytesReceived += written;
          if (lockStats()) { bytesReceived += written; unlockStats(); }
          if (ch.deferredReadOffset >= ch.deferredReadSize) {
            SAFE_FREE(ch.deferredReadData);
            ch.deferredReadData = nullptr;
            ch.deferredReadSize = 0;
            ch.deferredReadOffset = 0;
            LOGF_D("SSH", "Channel %d: Deferred buffer flushed", channelIndex);
          }
        } else if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
          LOGF_W("SSH", "Channel %d: Error flushing deferred buffer: %s", channelIndex, strerror(errno));
        }
      }
    }
  }

  // 1b) Flush deferred WRITE (Local->SSH)
  if (ch.deferredWriteData && ch.deferredWriteSize > ch.deferredWriteOffset) {
    if (ch.channel && isSocketWritable(ch.localSocket, 10)) {
      size_t remaining = ch.deferredWriteSize - ch.deferredWriteOffset;
      if (remaining > 0 && ch.deferredWriteData) {
        ssize_t written = libssh2_channel_write(ch.channel, (char*)ch.deferredWriteData + ch.deferredWriteOffset, remaining);
        if (written > 0) {
          ch.deferredWriteOffset += written;
          ch.totalBytesSent += written;
          if (lockStats()) { bytesSent += written; unlockStats(); }
          if (ch.deferredWriteOffset >= ch.deferredWriteSize) {
            SAFE_FREE(ch.deferredWriteData);
            ch.deferredWriteData = nullptr;
            ch.deferredWriteSize = 0;
            ch.deferredWriteOffset = 0;
            LOGF_D("SSH", "Channel %d: Deferred WRITE buffer flushed", channelIndex);
          }
        } else if (written < 0 && written != LIBSSH2_ERROR_EAGAIN) {
          LOGF_W("SSH", "Channel %d: Error flushing deferred WRITE buffer: %d", channelIndex, (int)written);
        }
      }
    }
  }

  // 2) Traiter les données en attente pour SSH->Local
  while (!ch.pendingWriteQueue.empty()) {
    PendingData& data = ch.pendingWriteQueue.front();
    
    // Vérifier si les données ne sont pas trop anciennes
    if (now - data.timestamp > maxAge) {
      LOGF_W("SSH", "Channel %d: Dropping aged pending write data (%d bytes)", 
             channelIndex, data.size - data.offset);
      SAFE_FREE(data.data);
      ch.pendingWriteQueue.pop();
      continue;
    }
    
    size_t remaining = data.size - data.offset;
    ssize_t written = send(ch.localSocket, data.data + data.offset, remaining, MSG_DONTWAIT);
    
    if (written > 0) {
      data.offset += written;
      ch.totalBytesReceived += written;
      if (lockStats()) {
        bytesReceived += written;
        unlockStats();
      }
      
      if (data.offset >= data.size) {
        // Données complètement envoyées
        SAFE_FREE(data.data);
        ch.pendingWriteQueue.pop();
        if (ch.queuedBytesToLocal >= data.size) ch.queuedBytesToLocal -= data.size; else ch.queuedBytesToLocal = 0;
        ch.lastSuccessfulWrite = now;
        LOGF_D("SSH", "Channel %d: Pending write completed (%d bytes)", channelIndex, data.size);
      }
    } else if (written < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        // Erreur permanente
        LOGF_W("SSH", "Channel %d: Error writing pending data: %s", channelIndex, strerror(errno));
        SAFE_FREE(data.data);
        ch.pendingWriteQueue.pop();
        ch.consecutiveErrors++;
      }
      break; // Arrêter le traitement si le socket n'est pas prêt
    }
  }

  // 3) Traiter les données en attente pour Local->SSH
  while (!ch.pendingReadQueue.empty()) {
    PendingData& data = ch.pendingReadQueue.front();
    
    // Vérifier si les données ne sont pas trop anciennes
    if (now - data.timestamp > maxAge) {
      LOGF_W("SSH", "Channel %d: Dropping aged pending read data (%d bytes)", 
             channelIndex, data.size - data.offset);
      SAFE_FREE(data.data);
      ch.pendingReadQueue.pop();
      continue;
    }
    
    size_t remaining = data.size - data.offset;
    ssize_t written = libssh2_channel_write(ch.channel, (char *)data.data + data.offset, remaining);
    
    if (written > 0) {
      data.offset += written;
      ch.totalBytesSent += written;
      if (lockStats()) {
        bytesSent += written;
        unlockStats();
      }
      
      if (data.offset >= data.size) {
        // Données complètement envoyées
        SAFE_FREE(data.data);
        ch.pendingReadQueue.pop();
        if (ch.queuedBytesToRemote >= data.size) ch.queuedBytesToRemote -= data.size; else ch.queuedBytesToRemote = 0;
        ch.lastSuccessfulRead = now;
        LOGF_D("SSH", "Channel %d: Pending read completed (%d bytes)", channelIndex, data.size);
      }
    } else if (written < 0) {
      if (written != LIBSSH2_ERROR_EAGAIN) {
        // Erreur permanente
        LOGF_W("SSH", "Channel %d: Error writing pending SSH data: %d", channelIndex, written);
        SAFE_FREE(data.data);
        ch.pendingReadQueue.pop();
        ch.consecutiveErrors++;
      }
      break; // Arrêter le traitement si le canal n'est pas prêt
    }
  }
  // 4) Relancer le flow control si on est repassé sous le LOW watermark
  static const size_t LOW_WATER_LOCAL = 24 * 256; // KB
  if (ch.flowControlPaused && ch.queuedBytesToLocal < LOW_WATER_LOCAL) {
    ch.flowControlPaused = false;
    LOGF_I("SSH", "Channel %d: Flow control RESUME (queuedToLocal=%d)", channelIndex, (int)ch.queuedBytesToLocal);
  }
}

bool SSHTunnel::queueData(int channelIndex, uint8_t* data, size_t size, bool isRead) {
  TunnelChannel &ch = channels[channelIndex];
  const size_t maxQueueSize = 1024; // Cap éléments, pas de blocage
  std::queue<PendingData>& targetQueue = isRead ? ch.pendingWriteQueue : ch.pendingReadQueue;

  if (targetQueue.size() >= maxQueueSize) {
    if (isRead) {
      // Utiliser / étendre le buffer différé plutôt que bloquer (SSH->Local)
      if (ch.deferredReadData == nullptr) {
        ch.deferredReadData = (uint8_t*)safeMalloc(size, "DEFERRED_READ");
        if (!ch.deferredReadData) {
          LOGF_E("SSH", "Channel %d: safeMalloc failed (deferred %d bytes)", channelIndex, size);
          return false;
        }
        memcpy(ch.deferredReadData, data, size);
        ch.deferredReadSize = size;
        ch.deferredReadOffset = 0;
        LOGF_W("SSH", "Channel %d: Deferred buffer created (%d bytes)", channelIndex, size);
        return true;
      } else if (ch.deferredReadSize + size < 32 * 1024) {
        uint8_t* newBuf = (uint8_t*)safeRealloc(ch.deferredReadData, ch.deferredReadSize + size, "DEFERRED_READ_EXT");
        if (newBuf) {
          memcpy(newBuf + ch.deferredReadSize, data, size);
          ch.deferredReadData = newBuf;
          ch.deferredReadSize += size;
          LOGF_W("SSH", "Channel %d: Deferred buffer extended (+%d => %d bytes)", channelIndex, size, (int)ch.deferredReadSize);
          return true;
        } else {
          LOGF_E("SSH", "Channel %d: Failed to extend deferred buffer", channelIndex);
          return false;
        }
      } else {
        LOGF_W("SSH", "Channel %d: Deferred buffer limit reached (%d bytes) - dropping new chunk", channelIndex, (int)ch.deferredReadSize);
        return false;
      }
    } else {
      // Buffer différé pour Local->SSH
      if (ch.deferredWriteData == nullptr) {
        ch.deferredWriteData = (uint8_t*)safeMalloc(size, "DEFERRED_WRITE");
        if (!ch.deferredWriteData) {
          LOGF_E("SSH", "Channel %d: safeMalloc failed (deferredWrite %d bytes)", channelIndex, size);
          return false;
        }
        memcpy(ch.deferredWriteData, data, size);
        ch.deferredWriteSize = size;
        ch.deferredWriteOffset = 0;
        LOGF_W("SSH", "Channel %d: Deferred WRITE buffer created (%d bytes)", channelIndex, size);
        return true;
  } else if (ch.deferredWriteSize + size < 48 * 1024) {
        uint8_t* newBuf = (uint8_t*)safeRealloc(ch.deferredWriteData, ch.deferredWriteSize + size, "DEFERRED_WRITE_EXT");
        if (newBuf) {
          memcpy(newBuf + ch.deferredWriteSize, data, size);
          ch.deferredWriteData = newBuf;
          ch.deferredWriteSize += size;
          LOGF_W("SSH", "Channel %d: Deferred WRITE buffer extended (+%d => %d bytes)", channelIndex, size, (int)ch.deferredWriteSize);
          return true;
        } else {
          LOGF_E("SSH", "Channel %d: Failed to extend deferred WRITE buffer", channelIndex);
          return false;
        }
      } else {
        ch.lostWriteChunks++;
        LOGF_W("SSH", "Channel %d: Deferred WRITE buffer limit reached (%d bytes) - dropping new chunk! Total lost: %d", channelIndex, (int)ch.deferredWriteSize, ch.lostWriteChunks);
        return false;
      }
    }
  }

  uint8_t* dataCopy = (uint8_t*)safeMalloc(size, "PENDING_DATA");
  if (!dataCopy) {
    LOGF_E("SSH", "Channel %d: safeMalloc failed for %d bytes", channelIndex, size);
    return false;
  }

  memcpy(dataCopy, data, size);

  PendingData pendingData = {
    .data = dataCopy,
    .size = size,
    .offset = 0,
    .timestamp = millis()
  };

  targetQueue.push(pendingData);
  if (isRead) ch.queuedBytesToLocal += size; else ch.queuedBytesToRemote += size;

  LOGF_D("SSH", "Channel %d: Queued %d bytes (%s), queue size: %d", 
         channelIndex, size, isRead ? "write" : "read", targetQueue.size());
  return true;
}

void SSHTunnel::flushPendingData(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  
  // Vider la queue d'écriture
  while (!ch.pendingWriteQueue.empty()) {
    PendingData data = ch.pendingWriteQueue.front();
    ch.pendingWriteQueue.pop();
    SAFE_FREE(data.data);
  if (ch.queuedBytesToLocal >= data.size) ch.queuedBytesToLocal -= data.size; else ch.queuedBytesToLocal = 0;
  }
  
  // Vider la queue de lecture
  while (!ch.pendingReadQueue.empty()) {
    PendingData data = ch.pendingReadQueue.front();
    ch.pendingReadQueue.pop();
    SAFE_FREE(data.data);
  if (ch.queuedBytesToRemote >= data.size) ch.queuedBytesToRemote -= data.size; else ch.queuedBytesToRemote = 0;
  }
  
  LOGF_D("SSH", "Channel %d: Pending data flushed", channelIndex);
}

bool SSHTunnel::isChannelHealthy(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active) {
    return false;
  }
  
  unsigned long now = millis();
  
  // Vérifier les erreurs consécutives
  if (ch.consecutiveErrors > 3) {
    return false;
  }
  
  // Vérifier la dernière activité
  if (now - ch.lastActivity > 300000) { // 5 minutes
    return false;
  }
  
  // Vérifier si les queues ne sont pas trop pleines
  if (ch.pendingWriteQueue.size() > 28 || ch.pendingReadQueue.size() > 28) {
    return false;
  }
  const size_t MAX_QUEUED_BYTES = 64 * 1024; // 64KB par canal
  if (ch.queuedBytesToLocal + ch.queuedBytesToRemote > MAX_QUEUED_BYTES) {
    return false;
  }
  
  return true;
}

void SSHTunnel::recoverChannel(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  
  LOGF_I("SSH", "Channel %d: Attempting recovery", channelIndex);
  
  // Vider les données en attente qui pourraient être corrompues
  flushPendingData(channelIndex);
  
  // Reset des compteurs d'erreurs
  ch.consecutiveErrors = 0;
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
  LOGF_I("SSH", "Channel %d: Recovery completed", channelIndex);
}

size_t SSHTunnel::getOptimalBufferSize(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  size_t baseSize = config->getConnectionConfig().bufferSize;
  
  // Réduire la taille du buffer si on a des problèmes de performance
  if (ch.consecutiveErrors > 2) {
    return baseSize / 2;
  }
  
  // Réduire si les queues sont pleines
  if (ch.pendingWriteQueue.size() > 5 || ch.pendingReadQueue.size() > 5) {
    return baseSize / 4;
  }
  
  return baseSize;
}

bool SSHTunnel::isSocketReadable(int sockfd, int timeoutMs) {
  if (sockfd < 0) return false;
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(sockfd, &rfds);
  struct timeval tv;
  tv.tv_sec  = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  int r = lwip_select(sockfd + 1, &rfds, nullptr, nullptr, (timeoutMs >= 0 ? &tv : nullptr));
  if (r <= 0) return false;
  return FD_ISSET(sockfd, &rfds);
}

bool SSHTunnel::isSocketWritable(int sockfd, int timeoutMs) {
  if (sockfd < 0) return false;
  fd_set wfds;
  FD_ZERO(&wfds);
  FD_SET(sockfd, &wfds);
  struct timeval tv;
  tv.tv_sec  = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  int r = lwip_select(sockfd + 1, nullptr, &wfds, nullptr, (timeoutMs >= 0 ? &tv : nullptr));
  if (r <= 0) return false;
  return FD_ISSET(sockfd, &wfds);
}