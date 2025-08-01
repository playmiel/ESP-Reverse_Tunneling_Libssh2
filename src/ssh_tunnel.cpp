#include "ssh_tunnel.h"
#include "network_optimizations.h"
#include "memory_fixes.h"

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
    if (!channels[i].active) {
      channelIndex = i;
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
  bool dataTransferred = false;
  int bufferSize = config->getConnectionConfig().bufferSize;

  // Si le canal est en pause pour congestion, on ne traite rien
  if (ch.flowControlPaused) {
    // Vérifier si on peut reprendre (après 50ms de pause)
    if (now - ch.lastActivity > 50) {
      ch.flowControlPaused = false;
      ch.pendingBytes = 0;
      LOGF_D("SSH", "Channel %d: Flow control resumed", channelIndex);
    } else {
      return; // Encore en pause
    }
  }

  // SSH -> Local avec contrôle de flux (utilise readMutex)
  if (lockChannelRead(channelIndex)) {
    // Double vérification après acquisition du mutex
    if (ch.active && ch.channel && ch.localSocket >= 0) {
      ssize_t rc = libssh2_channel_read(ch.channel, (char *)rxBuffer, bufferSize);
      if (rc > 0) {
        ssize_t totalWritten = 0;
        ssize_t remaining = rc;
        int retryCount = 0;
        const int maxRetries = 10;
        
        while (remaining > 0 && retryCount < maxRetries) {
          ssize_t written = send(ch.localSocket, rxBuffer + totalWritten, remaining, MSG_DONTWAIT);
          if (written > 0) {
            totalWritten += written;
            remaining -= written;
            dataTransferred = true;
            retryCount = 0;
          } else if (written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              // Socket local plein - activer contrôle de flux
              ch.pendingBytes += remaining;
              if (ch.pendingBytes > bufferSize && retryCount > 3) {
                ch.flowControlPaused = true;
                ch.lastActivity = now;
                LOGF_D("SSH", "Channel %d: Flow control activated for local write (pending: %d)", channelIndex, ch.pendingBytes);
                unlockChannelRead(channelIndex);
                return;
              }
              vTaskDelay(pdMS_TO_TICKS(2));
              retryCount++;
              continue;
            } else if (errno == ECONNRESET || errno == EPIPE) {
              LOGF_W("SSH", "Channel %d: Connection reset by peer during write", channelIndex);
              unlockChannelRead(channelIndex);
              closeChannel(channelIndex);
              return;
            } else {
              LOGF_W("SSH", "Channel %d: Local write error: %s", channelIndex, strerror(errno));
              unlockChannelRead(channelIndex);
              closeChannel(channelIndex);
              return;
            }
          } else {
            LOGF_I("SSH", "Channel %d: local socket closed during write", channelIndex);
            unlockChannelRead(channelIndex);
            closeChannel(channelIndex);
            return;
          }
        }
        
        // Si on n'arrive toujours pas à écrire, on active le contrôle de flux au lieu de fermer
        if (retryCount >= maxRetries && remaining > 0) {
          ch.flowControlPaused = true;
          ch.pendingBytes = remaining;
          ch.lastActivity = now;
          LOGF_W("SSH", "Channel %d: Local write blocked - activating flow control", channelIndex);
          unlockChannelRead(channelIndex);
          return;
        }
        
        if (totalWritten > 0) {
          if (lockStats()) {
            bytesReceived += totalWritten;
            unlockStats();
          }
          ch.lastActivity = now;
          ch.pendingBytes = 0; // Reset car on a réussi à écrire
          LOGF_D("SSH", "Channel %d: SSH->Local %d bytes", channelIndex, totalWritten);
        }
      } else if (rc < 0 && rc != LIBSSH2_ERROR_EAGAIN) {
        LOGF_W("SSH", "Channel %d read error: %d", channelIndex, rc);
        unlockChannelRead(channelIndex);
        closeChannel(channelIndex);
        return;
      }
    }
    unlockChannelRead(channelIndex);
  }

  // Local -> SSH avec contrôle de flux (utilise writeMutex)
  if (lockChannelWrite(channelIndex)) {
    // Double vérification après acquisition du mutex
    if (ch.active && ch.channel && ch.localSocket >= 0) {
      ssize_t bytesRead = recv(ch.localSocket, txBuffer, bufferSize, MSG_DONTWAIT);
      if (bytesRead > 0) {
        ssize_t totalWritten = 0;
        ssize_t remaining = bytesRead;
        int retryCount = 0;
        const int maxRetries = 10;
        
        while (remaining > 0 && retryCount < maxRetries) {
          ssize_t written = libssh2_channel_write(ch.channel, (char *)txBuffer + totalWritten, remaining);
          if (written > 0) {
            totalWritten += written;
            remaining -= written;
            dataTransferred = true;
            retryCount = 0;
          } else if (written < 0) {
            if (written == LIBSSH2_ERROR_EAGAIN) {
              // Canal SSH plein - activer contrôle de flux
              ch.pendingBytes += remaining;
              if (ch.pendingBytes > bufferSize && retryCount > 3) {
                ch.flowControlPaused = true;
                ch.lastActivity = now;
                LOGF_D("SSH", "Channel %d: Flow control activated for SSH write (pending: %d)", channelIndex, ch.pendingBytes);
                unlockChannelWrite(channelIndex);
                return;
              }
              vTaskDelay(pdMS_TO_TICKS(5));
              retryCount++;
              continue;
            } else {
              LOGF_W("SSH", "Channel %d write error: %d", channelIndex, written);
              unlockChannelWrite(channelIndex);
              closeChannel(channelIndex);
              return;
            }
          } else {
            vTaskDelay(pdMS_TO_TICKS(2));
            retryCount++;
            continue;
          }
        }
        
        // Si on n'arrive toujours pas à écrire, on active le contrôle de flux au lieu de fermer
        if (retryCount >= maxRetries && remaining > 0) {
          ch.flowControlPaused = true;
          ch.pendingBytes = remaining;
          ch.lastActivity = now;
          LOGF_W("SSH", "Channel %d: SSH write blocked - activating flow control", channelIndex);
          unlockChannelWrite(channelIndex);
          return;
        }
        
        if (totalWritten > 0) {
          if (lockStats()) {
            bytesSent += totalWritten;
            unlockStats();
          }
          ch.lastActivity = now;
          ch.pendingBytes = 0; // Reset car on a réussi à écrire
          LOGF_D("SSH", "Channel %d: Local->SSH %d bytes", channelIndex, totalWritten);
        }
      } else if (bytesRead == 0) {
        LOGF_I("SSH", "Channel %d: local socket closed", channelIndex);
        unlockChannelWrite(channelIndex);
        closeChannel(channelIndex);
        return;
      } else if (bytesRead < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // Pas de données disponibles, c'est normal
        } else if (errno == ECONNRESET || errno == EPIPE) {
          LOGF_W("SSH", "Channel %d: Connection reset by peer during read", channelIndex);
          unlockChannelWrite(channelIndex);
          closeChannel(channelIndex);
          return;
        } else {
          LOGF_W("SSH", "Channel %d: Local read error: %s", channelIndex, strerror(errno));
          unlockChannelWrite(channelIndex);
          closeChannel(channelIndex);
          return;
        }
      }

      // Check if SSH channel is closed
      if (libssh2_channel_eof(ch.channel)) {
        LOGF_I("SSH", "Channel %d: SSH channel closed", channelIndex);
        unlockChannelWrite(channelIndex);
        closeChannel(channelIndex);
        return;
      }
    }
    unlockChannelWrite(channelIndex);
  }

  if (dataTransferred) {
    ch.lastActivity = now;
  }
}

void SSHTunnel::closeChannel(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active)
    return;

  unsigned long sessionDuration = millis() - ch.lastActivity;
  
  // Log détaillé pour le debugging
  LOGF_I("SSH", "Closing channel %d (session: %lums, pending: %d, flow_paused: %s)", 
         channelIndex, sessionDuration, ch.pendingBytes, ch.flowControlPaused ? "yes" : "no");

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

  LOGF_I("SSH", "Channel %d closed and ready for reuse", channelIndex);
}

void SSHTunnel::cleanupInactiveChannels() {
  unsigned long now = millis();
  int maxChannels = config->getConnectionConfig().maxChannels;
  int channelTimeout = config->getConnectionConfig().channelTimeoutMs;
  int activeBefore = getActiveChannels();

  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active) {
      unsigned long timeSinceActivity = now - channels[i].lastActivity;
      
      // Nettoyage intelligent selon l'état du canal
      bool shouldClose = false;
      
      // Timeout normal (mais pas si en flow control récent)
      if (timeSinceActivity > channelTimeout && !channels[i].flowControlPaused) {
        shouldClose = true;
        LOGF_W("SSH", "Channel %d timeout after %lums, closing", i, timeSinceActivity);
      }
      // Canaux en flow control depuis trop longtemps (2 minutes)
      else if (channels[i].flowControlPaused && timeSinceActivity > 120000) {
        shouldClose = true;
        LOGF_W("SSH", "Channel %d stuck in flow control for %lums, closing", i, timeSinceActivity);
      }
      // Canaux avec des erreurs persistantes (pending bytes trop élevés depuis longtemps)
      else if (channels[i].pendingBytes > 0 && timeSinceActivity > 60000) {
        shouldClose = true;
        LOGF_W("SSH", "Channel %d has pending bytes (%d) for %lums, closing", i, channels[i].pendingBytes, timeSinceActivity);
      }
      
      if (shouldClose) {
        closeChannel(i);
      }
    }
  }
  
  // Log périodique de l'état des canaux (toutes les 30 secondes)
  static unsigned long lastLog = 0;
  if (now - lastLog > 30000) {
    int activeAfter = getActiveChannels();
    if (activeBefore != activeAfter) {
      LOGF_I("SSH", "Channel cleanup: %d -> %d active channels", activeBefore, activeAfter);
    }
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