#include "ssh_tunnel.h"
#include "network_optimizations.h"
#include "memory_fixes.h"
#include "lwip/sockets.h"

// Définir la taille de buffer pour les chunks de données
#define SSH_BUFFER_SIZE 1024

SSHTunnel::SSHTunnel()
    : session(nullptr), listener(nullptr), socketfd(-1),
      state(TUNNEL_DISCONNECTED), lastKeepAlive(0), lastConnectionAttempt(0),
      reconnectAttempts(0), bytesReceived(0), bytesSent(0),
      channels(nullptr), rxBuffer(nullptr), txBuffer(nullptr),
      tunnelMutex(nullptr), statsMutex(nullptr), pendingConnectionsMutex(nullptr), 
      config(&globalSSHConfig) {

  // Créer les sémaphores de protection
  tunnelMutex = xSemaphoreCreateMutex();
  statsMutex = xSemaphoreCreateMutex();
  pendingConnectionsMutex = xSemaphoreCreateMutex();
  
  if (tunnelMutex == NULL || statsMutex == NULL || pendingConnectionsMutex == NULL) {
    LOG_E("SSH", "Failed to create tunnel mutexes");
  }
}

SSHTunnel::~SSHTunnel() {
  disconnect();
  
  // Libérer les sémaphores
  SAFE_DELETE_SEMAPHORE(tunnelMutex);
  SAFE_DELETE_SEMAPHORE(statsMutex);
  SAFE_DELETE_SEMAPHORE(pendingConnectionsMutex);
  
  // Nettoyer les connexions en attente
  for (auto& pending : pendingConnections) {
    if (pending.channel) {
      libssh2_channel_close(pending.channel);
      libssh2_channel_free(pending.channel);
    }
  }
  pendingConnections.clear();
  
  // Libérer la mémoire allouée dynamiquement avec ring buffers
  if (channels != nullptr) {
    for (int i = 0; i < config->getConnectionConfig().maxChannels; i++) {
      // Nettoyer les ring buffers
      if (channels[i].writeRing) {
        delete channels[i].writeRing;
        channels[i].writeRing = nullptr;
      }
      if (channels[i].readRing) {
        delete channels[i].readRing;
        channels[i].readRing = nullptr;
      }
      if (channels[i].deferredWriteRing) {
        delete channels[i].deferredWriteRing;
        channels[i].deferredWriteRing = nullptr;
      }
      if (channels[i].deferredReadRing) {
        delete channels[i].deferredReadRing;
        channels[i].deferredReadRing = nullptr;
      }
      
      // CRITIQUE: Libérer les buffers différés dans le destructeur
      if (channels[i].deferredReadData) {
        SAFE_FREE(channels[i].deferredReadData);
      }
      if (channels[i].deferredWriteData) {
        SAFE_FREE(channels[i].deferredWriteData);
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
  
  // Initialiser les canaux avec ring buffers
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
    channels[i].lostWriteChunks = 0;
    
    // NOUVEAU: Initialiser les variables de détection des gros transferts
    channels[i].largeTransferInProgress = false;
    channels[i].transferStartTime = 0;
    channels[i].transferredBytes = 0;
    channels[i].peakBytesPerSecond = 0;
    
    // NOUVEAU: Créer les ring buffers
    char ringName[32];
    
    // Ring buffer pour SSH->Local (64 éléments)
    snprintf(ringName, sizeof(ringName), "CH%d_WRITE", i);
    channels[i].writeRing = new PendingDataRing(64, ringName);
    

    // Ring buffer pour Local->SSH (64 éléments)  
    snprintf(ringName, sizeof(ringName), "CH%d_READ", i);
    channels[i].readRing = new PendingDataRing(64, ringName);
    
    // Buffer continu pour SSH->Local (8KB)
    snprintf(ringName, sizeof(ringName), "CH%d_DEF_RD", i);
    channels[i].deferredReadRing = new DataRingBuffer(8 * 1024, ringName);
    
    // Buffer continu pour Local->SSH (8KB)
    snprintf(ringName, sizeof(ringName), "CH%d_DEF_WR", i);
    channels[i].deferredWriteRing = new DataRingBuffer(8 * 1024, ringName);
    
    if (!channels[i].writeRing || !channels[i].readRing || 
        !channels[i].deferredReadRing || !channels[i].deferredWriteRing) {
      LOGF_E("SSH", "Failed to create ring buffers for channel %d", i);
      unlockTunnel();
      return false;
    }
    

    // Créer des sémaphores binaires au lieu de mutex pour éviter priority inheritance issues
    channels[i].readMutex = xSemaphoreCreateBinary();
    channels[i].writeMutex = xSemaphoreCreateBinary();
    
    if (channels[i].readMutex == NULL || channels[i].writeMutex == NULL) {
      LOGF_E("SSH", "Failed to create semaphores for channel %d", i);
      unlockTunnel();
      return false;
    }
    
    // Libérer les sémaphores binaires pour les rendre disponibles
    xSemaphoreGive(channels[i].readMutex);
    xSemaphoreGive(channels[i].writeMutex);
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

  // NOUVEAU: Vérification de deadlock tous les 10 secondes
  static unsigned long lastDeadlockCheck = 0;
  if (now - lastDeadlockCheck > 10000) { // 10 secondes
    checkAndRecoverDeadlocks();
    lastDeadlockCheck = now;
  }

  // NOUVEAU: Diagnostic des transferts toutes les 30 secondes pour détecter les duplications
  static unsigned long lastTransferStatsCheck = 0;
  if (now - lastTransferStatsCheck > 30000) { // 30 secondes
    int maxChannels = config->getConnectionConfig().maxChannels;
    for (int i = 0; i < maxChannels; i++) {
      if (channels[i].active) {
        printDataTransferStats(i);
      }
    }
    lastTransferStatsCheck = now;
  }

  // Handle new connections
  handleNewConnection();
  
  // NOUVEAU: Traiter les connexions en attente si aucun gros transfert n'est actif
  if (!isLargeTransferActive()) {
    processPendingConnections();
  }

  // Handle data for existing channels
  int maxChannels = config->getConnectionConfig().maxChannels;
  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active) {
      // NOUVEAU: Flusher en priorité les buffers différés si ils sont pleins

      if (channels[i].deferredWriteRing && channels[i].deferredWriteRing->size() > 4 * 1024) {

        processPendingData(i); // Flush prioritaire
      }
      handleChannelData(i);
      
      // Traitement supplémentaire pour les canaux en fermeture gracieuse
      if (channels[i].gracefulClosing) {
        processPendingData(i); // S'assurer que les données sont transmises
      }
    }
  }

  // Cleanup inactive channels
  cleanupInactiveChannels();
  
  // Utiliser vTaskDelay au lieu de delay pour être plus compatible FreeRTOS
  vTaskDelay(pdMS_TO_TICKS(5)); // 5ms au lieu de 1ms pour réduire la contention
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

  // NOUVEAU: Vérifier si on doit accepter la connexion ou la mettre en attente
  // CORRECTION: Désactiver temporairement la queue pour éviter les problèmes
  if (!shouldAcceptNewConnection()) {
    LOGF_W("SSH", "All channels busy - rejecting new connection");
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);
    return false; // Rejeter directement au lieu de mettre en queue
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
  
  // NOUVEAU: Initialiser les variables de détection des gros transferts
  channels[channelIndex].largeTransferInProgress = false;
  channels[channelIndex].transferStartTime = millis();
  channels[channelIndex].transferredBytes = 0;
  channels[channelIndex].peakBytesPerSecond = 0;

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

  // PROTECTION: Éviter la contention excessive des mutex
  static unsigned long lastProcessTime[10] = {0}; // Assumant max 10 canaux
  if (channelIndex < 10 && (now - lastProcessTime[channelIndex]) < 5) {
    return; // Skip si traité récemment
  }
  lastProcessTime[channelIndex] = now;

  // Traiter d'abord les données en attente pour éviter l'accumulation
  processPendingData(channelIndex);

  // SSH -> Local (lecture du canal SSH et écriture vers socket local)
  bool readSuccess = processChannelRead(channelIndex);
  
  // Local -> SSH (lecture du socket local et écriture vers canal SSH)
  bool writeSuccess = processChannelWrite(channelIndex);

  // NOUVEAU: Détecter les gros transferts basé sur l'activité
  if (readSuccess || writeSuccess) {
    detectLargeTransfer(channelIndex);
  }

  // Mettre à jour l'activité si des données ont été transférées
  if (readSuccess || writeSuccess) {
    ch.lastActivity = now;
    ch.consecutiveErrors = 0; // Reset des erreurs après succès
  }

  // Vérifier si le canal doit être fermé proprement
  if (ch.gracefulClosing) {
    // Forcer le traitement des données en attente avant la fermeture
    processPendingData(channelIndex);
    
    // Vérifier si tous les ring buffers sont vraiment vides
    bool allEmpty = ch.writeRing->empty() && ch.readRing->empty() && 
                   ch.deferredWriteRing->empty() && ch.deferredReadRing->empty();
    
    if (allEmpty) {
      LOGF_I("SSH", "Channel %d: Graceful close completed - all buffers empty", channelIndex);
      closeChannel(channelIndex);
    } else {
      // Log l'état des buffers pour diagnostic
      LOGF_D("SSH", "Channel %d: Graceful close waiting - buffers: w=%zu, r=%zu, dw=%zu, dr=%zu", 
             channelIndex, 
             ch.writeRing->size(), ch.readRing->size(),
             ch.deferredWriteRing->size(), ch.deferredReadRing->size());
    }
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
    // Protection atomique : marquer le socket comme fermé avant fermeture réelle
    int socketToClose = ch.localSocket;
    ch.localSocket = -1; // Éviter les race conditions
    
    // Arrêt propre des opérations
    shutdown(socketToClose, SHUT_RDWR);
    vTaskDelay(pdMS_TO_TICKS(10)); // Laisser le temps aux threads de voir le changement
    close(socketToClose);
    
    LOGF_D("SSH", "Channel %d: Local socket %d closed safely", channelIndex, socketToClose);
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
  
  // NOUVEAU: Reset des variables de détection des gros transferts
  ch.largeTransferInProgress = false;
  ch.transferStartTime = 0;
  ch.transferredBytes = 0;
  ch.peakBytesPerSecond = 0;
  
  // Vider les ring buffers au lieu des anciens pointeurs
  if (ch.deferredReadRing) {
    ch.deferredReadRing->clear();
  }
  if (ch.deferredWriteRing) {
    ch.deferredWriteRing->clear();
  }
  if (ch.writeRing) {
    PendingData dummy;
    while (ch.writeRing->pop(dummy)) { /* vider */ }
  }
  if (ch.readRing) {
    PendingData dummy;
    while (ch.readRing->pop(dummy)) { /* vider */ }
  }
  
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
        // Forcer le traitement des données restantes
        processPendingData(i);
        
        // Permettre plus de temps pour vider les ring buffers
        if (channels[i].writeRing->empty() && channels[i].readRing->empty() &&
            channels[i].deferredWriteRing->empty() && channels[i].deferredReadRing->empty()) {
          shouldClose = true;
          LOGF_I("SSH", "Channel %d graceful close completed", i);
        } else if (timeSinceActivity > 60000) { // 60 secondes au lieu de 30 pour graceful close
          shouldClose = true;
          LOGF_W("SSH", "Channel %d graceful close timeout - forcing close with pending data", i);
          LOGF_W("SSH", "Channel %d buffers: w=%zu, r=%zu, dw=%zu, dr=%zu", i,
                 channels[i].writeRing->size(), channels[i].readRing->size(),
                 channels[i].deferredWriteRing->size(), channels[i].deferredReadRing->size());
        } else {
          // Log périodique de l'état pendant la fermeture gracieuse
          static unsigned long lastGracefulLog[16] = {0}; // Pour 16 canaux max
          if (now - lastGracefulLog[i] > 5000) { // Log toutes les 5 secondes
            LOGF_I("SSH", "Channel %d graceful close in progress - buffers: w=%zu, r=%zu, dw=%zu, dr=%zu", i,
                   channels[i].writeRing->size(), channels[i].readRing->size(),
                   channels[i].deferredWriteRing->size(), channels[i].deferredReadRing->size());
            lastGracefulLog[i] = now;
          }
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
        // Ring buffers trop pleins depuis trop longtemps
        else if ((channels[i].writeRing->size() > 8 || channels[i].readRing->size() > 8) && 
                 timeSinceActivity > 60000) {
          shouldClose = true;
          LOGF_W("SSH", "Channel %d has full ring buffers for %lums, closing", i, timeSinceActivity);
        }
        // Données anciennes dans les ring buffers (plus de 10 secondes)
        else if (!channels[i].writeRing->empty() || !channels[i].readRing->empty()) {
          // Pour les ring buffers, on ne peut pas facilement vérifier l'âge
          // mais on peut essayer de traiter les données en attente
          if (timeSinceActivity > 10000) {
            LOGF_W("SSH", "Channel %d has old data in ring buffers, processing", i);
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
        totalQueued += channels[i].writeRing->size() + channels[i].readRing->size();
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
  
  // MONITORING: Surveiller les tentatives de verrouillage
  unsigned long start = millis();

  // Timeout réduit pour éviter les deadlocks (100ms au lieu de 200ms)
  BaseType_t result = xSemaphoreTake(channels[channelIndex].readMutex, pdMS_TO_TICKS(100));
  unsigned long duration = millis() - start;
  
  if (result != pdTRUE) {
    // Utiliser LOG_D au lieu de LOG_W pour réduire le spam de logs
    LOGF_D("SSH", "Channel %d: Could not acquire READ mutex after %lums", channelIndex, duration);
    return false;
  }
  
  if (duration > 25) { // Réduit de 50ms à 25ms

    LOGF_D("SSH", "Channel %d: READ mutex acquired after %lums (slow)", channelIndex, duration);
  }
  
  return true;
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
  
  // MONITORING: Surveiller les tentatives de verrouillage  
  unsigned long start = millis();

  // Timeout réduit pour éviter les deadlocks (100ms au lieu de 200ms)  
  BaseType_t result = xSemaphoreTake(channels[channelIndex].writeMutex, pdMS_TO_TICKS(100));
  unsigned long duration = millis() - start;
  
  if (result != pdTRUE) {
    // Utiliser LOG_D au lieu de LOG_W pour réduire le spam de logs
    LOGF_D("SSH", "Channel %d: Could not acquire WRITE mutex after %lums", channelIndex, duration);
    return false;
  }
  
  if (duration > 25) { // Réduit de 50ms à 25ms

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

  // NOUVEAU: Flow control avec high/low watermarks adaptés ESP32 - PLUS CONSERVATEUR
  static const size_t HIGH_WATER_LOCAL = 8 * 512; // 4KB (réduit de 8KB)
  static const size_t LOW_WATER_LOCAL = 2 * 512;  // 1KB pour reprendre plus tôt
  

  if (ch.flowControlPaused) {
    // Vérifier si on peut reprendre
    if (ch.queuedBytesToLocal < LOW_WATER_LOCAL) {
      ch.flowControlPaused = false;
      LOGF_I("SSH", "Channel %d: Flow control RESUME (queuedToLocal=%zu)", 
             channelIndex, ch.queuedBytesToLocal);
    } else {
      unlockChannelRead(channelIndex);
      return false; // Rester en pause
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
    // Vérifier l'état du socket avant écriture
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
      // DIAGNOSTIC: Vérifier la cohérence des données pour les gros transferts
      if (ch.largeTransferInProgress && bytesRead > 1024) {
        // Simple vérification - compter les bytes non-null pour détecter la corruption
        size_t nonNullBytes = 0;
        for (size_t i = 0; i < bytesRead; i++) {
          if (rxBuffer[i] != 0) nonNullBytes++;
        }
        
        // Si plus de 90% sont des zéros, c'est suspect
        if (nonNullBytes < (bytesRead * 0.1)) {
          LOGF_W("SSH", "Channel %d: Suspicious data pattern detected (%zu/%zd non-null)", 
                 channelIndex, nonNullBytes, bytesRead);
        }
      }
      
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
        
        // DIAGNOSTIC: Log pour suivre les gros transferts et détecter les problèmes
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
        } else if (errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN || 
                   errno == ESHUTDOWN || errno == ETIMEDOUT) {
          LOGF_I("SSH", "Channel %d: Local connection closed during write (%s), initiating graceful close", 
                 channelIndex, strerror(errno));
          ch.gracefulClosing = true;
          success = true; // Traiter comme fermeture normale
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

  // NOUVEAU: Flow control préventif basé sur le buffer différé

  if (ch.deferredWriteRing && ch.deferredWriteRing->size() > 8 * 1024) { // 8KB de données en attente
    LOGF_D("SSH", "Channel %d: Skipping read due to large deferred buffer (%zu bytes)", 
           channelIndex, ch.deferredWriteRing->size());

    return false; // Ne pas lire plus de données du socket local
  }

  if (!lockChannelWrite(channelIndex)) {
    return false;
  }

  bool success = false;
  size_t bufferSize = getOptimalBufferSize(channelIndex);
  unsigned long now = millis();

  // Double vérification après acquisition du mutex
  if (ch.active && ch.channel && ch.localSocket >= 0) {
    // Vérifier l'état du socket avec getsockopt pour détecter les erreurs
    int sockError = 0;
    socklen_t errLen = sizeof(sockError);
    if (getsockopt(ch.localSocket, SOL_SOCKET, SO_ERROR, &sockError, &errLen) == 0 && sockError != 0) {
      LOGF_I("SSH", "Channel %d: Socket error detected: %s, initiating graceful close", 
             channelIndex, strerror(sockError));
      ch.gracefulClosing = true;
      return false;
    }

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
        LOGF_I("SSH", "Channel %d: Local socket closed, initiating graceful close", channelIndex);
        ch.gracefulClosing = true;
        // Continuer à traiter les données en attente
        success = true; // Considérer comme un succès pour continuer le traitement
      } else if (bytesRead < 0) {
        int errorCode = errno;
        if (errorCode != EAGAIN && errorCode != EWOULDBLOCK) {
          if (errorCode == ECONNRESET || errorCode == EPIPE || errorCode == ENOTCONN || 
              errorCode == ESHUTDOWN || errorCode == ETIMEDOUT) {
            LOGF_I("SSH", "Channel %d: Local connection closed (%s), initiating graceful close", 
                   channelIndex, strerror(errorCode));
            ch.gracefulClosing = true;
            success = true; // Continuer le traitement des données restantes
          } else {
            LOGF_W("SSH", "Channel %d: Local read error: %s (errno=%d)", 
                   channelIndex, strerror(errorCode), errorCode);
            ch.consecutiveErrors++;
          }
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


  unsigned long now = esp_timer_get_time() / 1000; // millisecondes
  const unsigned long maxAge = 10000; // AUGMENTÉ: 10 secondes au lieu de 5 pour éviter les drops prématurés
  
  // CORRECTION: Espacer davantage les appels pour éviter la contention
  static unsigned long lastProcessTime[10] = {0};
  if (channelIndex < 10 && (now - lastProcessTime[channelIndex]) < 20) { // 20ms au lieu de 10ms
    return;
  }
  lastProcessTime[channelIndex] = now;
  
  // 1) Traiter les buffers différés avec protection MAIS SANS REMETTRE LES DONNÉES
  if (xSemaphoreTake(ch.readMutex, pdMS_TO_TICKS(20)) == pdTRUE) { // Timeout réduit
    // Flush du buffer différé SSH->Local
    if (ch.deferredReadRing && ch.deferredReadRing->size() > 0) {
      uint8_t tempBuffer[SSH_BUFFER_SIZE];
      size_t bytesRead = ch.deferredReadRing->read(tempBuffer, sizeof(tempBuffer));
      
      if (bytesRead > 0 && ch.localSocket >= 0 && isSocketWritable(ch.localSocket, 5)) {
        ssize_t written = send(ch.localSocket, tempBuffer, bytesRead, MSG_DONTWAIT);

        if (written > 0) {
          ch.totalBytesReceived += written;

          ch.queuedBytesToLocal = (ch.queuedBytesToLocal > written) ? ch.queuedBytesToLocal - written : 0;
          if (lockStats()) { 
            bytesReceived += written; 
            unlockStats(); 
          }
          
          // CRITIQUE: Si pas tout envoyé, créer un NOUVEAU buffer temporaire pour éviter la duplication
          if (written < bytesRead) {
            // Écrire directement les données restantes SEULEMENT si on a de la place
            if (ch.deferredReadRing->available() >= (bytesRead - written)) {
              ch.deferredReadRing->write(tempBuffer + written, bytesRead - written);
            } else {
              // Sinon, abandonner ces données pour éviter la duplication
              LOGF_W("SSH", "Channel %d: Dropping %zu bytes to prevent duplication", 
                     channelIndex, bytesRead - written);
            }

          }
          
          LOGF_D("SSH", "Channel %d: Processed %zd/%zu bytes from deferred read buffer", 
                 channelIndex, written, bytesRead);
        } else if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
          LOGF_W("SSH", "Channel %d: Error writing from deferred buffer: %s", 
                 channelIndex, strerror(errno));
          // NE PAS remettre les données - éviter la duplication
        }
        // Pour EAGAIN: NE PAS remettre les données, elles seront reprises au prochain appel
      }
    }
    
    xSemaphoreGive(ch.readMutex);
  }
  

  // 1b) Flush du buffer différé Local->SSH
  if (xSemaphoreTake(ch.writeMutex, pdMS_TO_TICKS(20)) == pdTRUE) { // Timeout réduit
    if (ch.deferredWriteRing && ch.deferredWriteRing->size() > 0) {
      uint8_t tempBuffer[SSH_BUFFER_SIZE];
      size_t bytesRead = ch.deferredWriteRing->read(tempBuffer, sizeof(tempBuffer));
      
      if (bytesRead > 0 && ch.channel) {
        ssize_t written = libssh2_channel_write(ch.channel, (char*)tempBuffer, bytesRead);

        if (written > 0) {
          ch.totalBytesSent += written;

          ch.queuedBytesToRemote = (ch.queuedBytesToRemote > written) ? ch.queuedBytesToRemote - written : 0;
          if (lockStats()) { 
            bytesSent += written; 
            unlockStats(); 
          }
          
          // CRITIQUE: Si pas tout envoyé, gérer les données restantes avec précaution
          if (written < bytesRead) {
            if (ch.deferredWriteRing->available() >= (bytesRead - written)) {
              ch.deferredWriteRing->write(tempBuffer + written, bytesRead - written);
            } else {
              LOGF_W("SSH", "Channel %d: Dropping %zu bytes to prevent duplication", 
                     channelIndex, bytesRead - written);
            }

          }
          
          LOGF_D("SSH", "Channel %d: Processed %zd/%zu bytes from deferred write buffer", 
                 channelIndex, written, bytesRead);
        } else if (written < 0 && written != LIBSSH2_ERROR_EAGAIN) {

          LOGF_W("SSH", "Channel %d: Error writing from deferred write buffer: %zd", 
                 channelIndex, written);
          // NE PAS remettre les données

        }
        // Pour EAGAIN: NE PAS remettre les données
      }
    }
    
    xSemaphoreGive(ch.writeMutex);
  }
  
  unlockChannelWrite(channelIndex);

  // 2) Traiter les données en attente pour SSH->Local (writeRing)
  if (xSemaphoreTake(ch.readMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
    PendingData pendingData;
    
    while (ch.writeRing->pop(pendingData)) {
      // Vérifications de sécurité des données
      if (pendingData.size == 0) {
        LOGF_W("SSH", "Channel %d: Skipping pendingData with size 0", channelIndex);
        continue;
      }
      
      if (pendingData.offset >= pendingData.size) {
        LOGF_W("SSH", "Channel %d: Skipping pendingData with offset >= size (%zu >= %zu)", 
               channelIndex, pendingData.offset, pendingData.size);
        continue;
      }
      
      if (pendingData.size > sizeof(pendingData.data)) {
        LOGF_E("SSH", "Channel %d: pendingData.size (%zu) > buffer size (%zu)", 
               channelIndex, pendingData.size, sizeof(pendingData.data));
        continue;
      }
      
      // Vérifier si les données ne sont pas trop anciennes
      if (now - pendingData.timestamp > maxAge) {
        LOGF_W("SSH", "Channel %d: Dropping aged pending write data (%zu bytes)", 
               channelIndex, pendingData.size);
        continue;
      }
      
      if (ch.localSocket >= 0 && isSocketWritable(ch.localSocket, 1)) {
        size_t remaining = pendingData.size - pendingData.offset;
        ssize_t written = send(ch.localSocket, 
                             pendingData.data + pendingData.offset, 
                             remaining, 
                             MSG_DONTWAIT);
        
        if (written > 0) {
          pendingData.offset += written;
          ch.totalBytesReceived += written;
          if (lockStats()) {
            bytesReceived += written;
            unlockStats();
          }
          
          if (pendingData.offset < pendingData.size) {
            // Pas tout envoyé - remettre dans le ring buffer AVEC PROTECTION CONTRE DUPLICATION
            if (!ch.writeRing->push(pendingData)) {
              // Ring buffer plein - utiliser le buffer différé SI il y a de la place
              if (ch.deferredReadRing->available() >= remaining) {
                ch.deferredReadRing->write(pendingData.data + pendingData.offset,
                                         pendingData.size - pendingData.offset);
              } else {
                LOGF_W("SSH", "Channel %d: Dropping %zu bytes from writeRing to prevent overflow", 
                       channelIndex, pendingData.size - pendingData.offset);
              }
            }
          } else {
            // Données complètement envoyées
            ch.lastSuccessfulWrite = now;
            if (ch.queuedBytesToLocal >= pendingData.size) {
              ch.queuedBytesToLocal -= pendingData.size;
            } else {
              ch.queuedBytesToLocal = 0;
            }
          }
        } else if (written < 0) {
          if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGF_W("SSH", "Channel %d: Error writing pending data: %s", 
                   channelIndex, strerror(errno));
            ch.consecutiveErrors++;
          } else {
            // EAGAIN - remettre les données AVEC PROTECTION
            if (!ch.writeRing->push(pendingData)) {
              if (ch.deferredReadRing->available() >= remaining) {
                ch.deferredReadRing->write(pendingData.data + pendingData.offset,
                                         pendingData.size - pendingData.offset);
              }
            }
          }
          break;
        }
      } else {
        // Socket pas prêt - remettre les données AVEC PROTECTION
        if (!ch.writeRing->push(pendingData)) {
          size_t remaining = pendingData.size - pendingData.offset;
          if (ch.deferredReadRing->available() >= remaining) {
            ch.deferredReadRing->write(pendingData.data + pendingData.offset, remaining);
          }
        }
        break;
      }
    }
    
    xSemaphoreGive(ch.readMutex);
  }

  // 3) Traiter les données en attente pour Local->SSH (readRing)
  if (xSemaphoreTake(ch.writeMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
    PendingData pendingData;
    
    while (ch.readRing->pop(pendingData)) {
      // Vérifications de sécurité des données
      if (pendingData.size == 0) {
        LOGF_W("SSH", "Channel %d: Skipping pendingData with size 0 (read)", channelIndex);
        continue;
      }
      
      if (pendingData.offset >= pendingData.size) {
        LOGF_W("SSH", "Channel %d: Skipping pendingData with offset >= size (%zu >= %zu) (read)", 
               channelIndex, pendingData.offset, pendingData.size);
        continue;
      }
      
      if (pendingData.size > sizeof(pendingData.data)) {
        LOGF_E("SSH", "Channel %d: pendingData.size (%zu) > buffer size (%zu) (read)", 
               channelIndex, pendingData.size, sizeof(pendingData.data));
        continue;
      }
      
      // Vérifier si les données ne sont pas trop anciennes
      if (now - pendingData.timestamp > maxAge) {
        LOGF_W("SSH", "Channel %d: Dropping aged pending read data (%zu bytes)", 
               channelIndex, pendingData.size);
        continue;
      }
      
      if (ch.channel) {
        size_t remaining = pendingData.size - pendingData.offset;
        ssize_t written = libssh2_channel_write(ch.channel, 
                                              (char*)(pendingData.data + pendingData.offset), 
                                              remaining);
        
        if (written > 0) {
          pendingData.offset += written;
          ch.totalBytesSent += written;
          if (lockStats()) {
            bytesSent += written;
            unlockStats();
          }
          
          if (pendingData.offset < pendingData.size) {
            // Pas tout envoyé - remettre dans le ring buffer AVEC PROTECTION
            if (!ch.readRing->push(pendingData)) {
              // Ring buffer plein - utiliser le buffer différé SI il y a de la place
              if (ch.deferredWriteRing->available() >= remaining) {
                ch.deferredWriteRing->write(pendingData.data + pendingData.offset,
                                          pendingData.size - pendingData.offset);
              } else {
                LOGF_W("SSH", "Channel %d: Dropping %zu bytes from readRing to prevent overflow", 
                       channelIndex, pendingData.size - pendingData.offset);
              }
            }
          } else {
            // Données complètement envoyées
            ch.lastSuccessfulRead = now;
            if (ch.queuedBytesToRemote >= pendingData.size) {
              ch.queuedBytesToRemote -= pendingData.size;
            } else {
              ch.queuedBytesToRemote = 0;
            }
          }
        } else if (written < 0) {
          if (written != LIBSSH2_ERROR_EAGAIN) {
            LOGF_W("SSH", "Channel %d: Error writing pending SSH data: %zd", 
                   channelIndex, written);
            ch.consecutiveErrors++;
          } else {
            // EAGAIN - remettre les données AVEC PROTECTION
            if (!ch.readRing->push(pendingData)) {
              if (ch.deferredWriteRing->available() >= remaining) {
                ch.deferredWriteRing->write(pendingData.data + pendingData.offset,
                                          pendingData.size - pendingData.offset);
              }
            }
          }
          break;
        }
      } else {
        // Canal pas disponible - remettre les données AVEC PROTECTION
        if (!ch.readRing->push(pendingData)) {
          size_t remaining = pendingData.size - pendingData.offset;
          if (ch.deferredWriteRing->available() >= remaining) {
            ch.deferredWriteRing->write(pendingData.data + pendingData.offset, remaining);
          }
        }
        break;
      }
    }
    
    xSemaphoreGive(ch.writeMutex);
  }

  // 4) Relancer le flow control si on est repassé sous le LOW watermark

  static const size_t LOW_WATER_LOCAL = 16 * 256; // 4KB

  if (ch.flowControlPaused && ch.queuedBytesToLocal < LOW_WATER_LOCAL) {
    ch.flowControlPaused = false;
    LOGF_I("SSH", "Channel %d: Flow control RESUME (queuedToLocal=%zu)", 
           channelIndex, ch.queuedBytesToLocal);
  }
}

bool SSHTunnel::queueData(int channelIndex, uint8_t* data, size_t size, bool isRead) {
  // Vérifications de sécurité initiales
  if (channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) {
    LOGF_E("SSH", "queueData: Invalid channel index %d", channelIndex);
    return false;
  }
  
  if (!data) {
    LOGF_E("SSH", "queueData: data pointer is NULL");
    return false;
  }
  
  if (size == 0) {
    LOGF_D("SSH", "queueData: size is 0, nothing to queue");
    return true; // Pas une erreur, juste rien à faire
  }
  
  if (size > SSH_BUFFER_SIZE) {
    LOGF_W("SSH", "queueData: size (%zu) > SSH_BUFFER_SIZE (%d), will fragment", 
           size, SSH_BUFFER_SIZE);
  }
  
  TunnelChannel &ch = channels[channelIndex];

  
  if (!ch.active) {
    LOGF_W("SSH", "queueData: Channel %d is not active", channelIndex);
    return false;
  }
  
  // Sélectionner le ring buffer approprié selon la direction
  PendingDataRing* targetRing = isRead ? ch.writeRing : ch.readRing;
  DataRingBuffer* deferredRing = isRead ? ch.deferredReadRing : ch.deferredWriteRing;
  
  // Sélectionner le bon sémaphore pour la synchronisation
  SemaphoreHandle_t semaphore = isRead ? ch.writeMutex : ch.readMutex;
  
  // Protéger l'accès avec sémaphore binaire (timeout 100ms)
  if (xSemaphoreTake(semaphore, pdMS_TO_TICKS(100)) != pdTRUE) {
    LOGF_W("SSH", "Channel %d: Failed to acquire %s semaphore for queueing %zu bytes", 
           channelIndex, isRead ? "write" : "read", size);
    return false;
  }
  
  // Essayer d'ajouter les données au ring buffer principal
  PendingData pendingData;
  pendingData.size = (size > SSH_BUFFER_SIZE) ? SSH_BUFFER_SIZE : size;
  pendingData.offset = 0;
  pendingData.timestamp = esp_timer_get_time() / 1000; // millisecondes
  
  // Vérifications de sécurité avant memcpy
  if (!data) {
    LOGF_E("SSH", "Channel %d: data pointer is NULL", channelIndex);
    xSemaphoreGive(semaphore);
    return false;
  }
  
  if (pendingData.size == 0) {
    LOGF_E("SSH", "Channel %d: pendingData.size is 0", channelIndex);
    xSemaphoreGive(semaphore);
    return false;
  }
  
  if (pendingData.size > sizeof(pendingData.data)) {
    LOGF_E("SSH", "Channel %d: pendingData.size (%zu) > buffer size (%zu)", 
           channelIndex, pendingData.size, sizeof(pendingData.data));
    xSemaphoreGive(semaphore);
    return false;
  }
  
  // Copier les données dans le buffer interne
  memcpy(pendingData.data, data, pendingData.size);
  
  // NOUVEAU: Calculer un checksum simple pour détecter les duplications
  pendingData.checksum = 0;
  for (size_t i = 0; i < pendingData.size; i++) {
    pendingData.checksum = pendingData.checksum * 31 + pendingData.data[i];
  }
  
  // NOUVEAU: Vérifier s'il y a déjà des données identiques dans le ring buffer
  if (targetRing->size() > 0) {
    PendingData existingData;
    if (targetRing->peek(existingData)) {
      if (existingData.checksum == pendingData.checksum && 
          existingData.size == pendingData.size &&
          memcmp(existingData.data, pendingData.data, pendingData.size) == 0) {
        // Duplication détectée !
        LOGF_W("SSH", "Channel %d: DUPLICATE DATA DETECTED! Size=%zu, checksum=0x%08X", 
               channelIndex, pendingData.size, pendingData.checksum);
        xSemaphoreGive(semaphore);
        return false; // Rejeter la duplication

      }
    }
  }
  
  if (targetRing->push(pendingData)) {
    // Succès - mettre à jour les statistiques
    if (isRead) {
      ch.queuedBytesToLocal += pendingData.size;
    } else {

      ch.queuedBytesToRemote += pendingData.size;

    }
    
    xSemaphoreGive(semaphore);
    
    // Si il reste des données, les traiter récursivement
    if (size > pendingData.size) {
      return queueData(channelIndex, data + pendingData.size, size - pendingData.size, isRead);
    }
    
    LOGF_D("SSH", "Channel %d: Queued %zu bytes (%s direction)", 
           channelIndex, size, isRead ? "SSH->Local" : "Local->SSH");
    return true;
  }
  
  // Ring buffer principal plein - essayer le buffer différé
  size_t bytesWritten = deferredRing->write(data, size);
  
  if (bytesWritten > 0) {
    // Succès partiel ou total avec buffer différé
    if (isRead) {
      ch.queuedBytesToLocal += bytesWritten;
    } else {
      ch.queuedBytesToRemote += bytesWritten;
    }
    
    if (bytesWritten < size) {
      ch.lostWriteChunks++;
      LOGF_W("SSH", "Channel %d: Deferred buffer partial write (%zu/%zu bytes), lost chunks: %d", 
             channelIndex, bytesWritten, size, ch.lostWriteChunks);
    } else {
      LOGF_D("SSH", "Channel %d: Used deferred buffer (%zu bytes)", channelIndex, bytesWritten);
    }
    
    xSemaphoreGive(semaphore);
    return (bytesWritten == size);
  }
  
  // Tous les buffers pleins
  ch.lostWriteChunks++;
  LOGF_W("SSH", "Channel %d: All buffers full - dropping %zu bytes! Total lost chunks: %d", 
         channelIndex, size, ch.lostWriteChunks);
  
  xSemaphoreGive(semaphore);
  return false;
}

void SSHTunnel::flushPendingData(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  
  // NOUVEAU: Utiliser un timeout très court pour éviter les deadlocks
  // et acquérir dans un ordre fixe pour éviter les blocages croisés
  const TickType_t SHORT_TIMEOUT = pdMS_TO_TICKS(10); // 10ms seulement
  
  // Ordre fixe: toujours readMutex puis writeMutex pour éviter les deadlocks
  bool readLocked = false, writeLocked = false;
  
  // Tenter d'acquérir readMutex en premier
  if (ch.readMutex && xSemaphoreTake(ch.readMutex, SHORT_TIMEOUT) == pdTRUE) {
    readLocked = true;
    
    // Puis writeMutex
    if (ch.writeMutex && xSemaphoreTake(ch.writeMutex, SHORT_TIMEOUT) == pdTRUE) {
      writeLocked = true;
      
      // Vider les ring buffers principaux
      PendingData dummy;
      size_t flushedWrite = 0, flushedRead = 0;
      
      if (ch.writeRing) {
        while (ch.writeRing->pop(dummy)) {
          flushedWrite++;
        }
      }
      
      if (ch.readRing) {
        while (ch.readRing->pop(dummy)) {
          flushedRead++;
        }
      }
      
      // Vider les buffers différés
      if (ch.deferredReadRing) {
        ch.deferredReadRing->clear();
      }
      if (ch.deferredWriteRing) {
        ch.deferredWriteRing->clear();
      }
      
      // Réinitialiser les compteurs
      ch.queuedBytesToLocal = 0;
      ch.queuedBytesToRemote = 0;
      
      LOGF_D("SSH", "Channel %d: Flushed %zu write entries and %zu read entries from ring buffers", 
             channelIndex, flushedWrite, flushedRead);
             
    } else {
      LOGF_D("SSH", "Channel %d: Could not acquire write mutex for flush (timeout)", channelIndex);
    }
  } else {
    LOGF_D("SSH", "Channel %d: Could not acquire read mutex for flush (timeout)", channelIndex);
  }
  
  // Libérer les mutex dans l'ordre inverse
  if (writeLocked) {
    xSemaphoreGive(ch.writeMutex);
  }
  if (readLocked) {
    xSemaphoreGive(ch.readMutex);
  }
}

bool SSHTunnel::isChannelHealthy(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  if (!ch.active) {
    return false;
  }
  
  unsigned long now = millis();
  
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
  

  // Vérifier si les ring buffers ne sont pas trop pleins (réduit les seuils)
  if (ch.writeRing && ch.writeRing->size() > 20) { // Réduit de 32 à 20
    LOGF_D("SSH", "Channel %d: Unhealthy due to write ring buffer size (%zu)", channelIndex, ch.writeRing->size());
    return false;
  }
  if (ch.readRing && ch.readRing->size() > 20) { // Réduit de 32 à 20
    LOGF_D("SSH", "Channel %d: Unhealthy due to read ring buffer size (%zu)", channelIndex, ch.readRing->size());
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
  
  LOGF_I("SSH", "Channel %d: Attempting recovery", channelIndex);
  
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
  
  // CORRECTION: Simplifier et être plus conservateur avec les buffers
  // Éviter les changements trop agressifs de taille qui peuvent causer des corruptions
  
  // Réduire la taille du buffer si on a des problèmes de performance
  if (ch.consecutiveErrors > 3) { // Plus tolérant
    return baseSize / 2;
  }
  
  // Réduire si les ring buffers sont très pleins
  if (ch.writeRing->size() > 15 || ch.readRing->size() > 15) { // Plus tolérant
    return baseSize / 2; // Moins agressif
  }
  
  // NOUVEAU: Pour les gros transferts, augmenter modérément mais pas trop
  if (ch.largeTransferInProgress && ch.consecutiveErrors == 0) {
    // Augmentation modérée et progressive
    size_t largeSize = baseSize * 2; // Seulement 2x au lieu de 4x-8x
    
    // Limiter strictement pour éviter les problèmes de mémoire
    const size_t MAX_BUFFER_SIZE = 16 * 1024; // 16KB max au lieu de 32KB
    return (largeSize > MAX_BUFFER_SIZE) ? MAX_BUFFER_SIZE : largeSize;
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
    
    // Vérifier si les ring buffers sont anormalement pleins
    bool buffersOverloaded = false;
    if (ch.writeRing && ch.writeRing->size() > 45) buffersOverloaded = true; // Plus de 45 éléments en attente
    if (ch.readRing && ch.readRing->size() > 45) buffersOverloaded = true;
    
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
  
  size_t writeRingSize = ch.writeRing ? ch.writeRing->size() : 0;
  size_t readRingSize = ch.readRing ? ch.readRing->size() : 0;
  size_t deferredWriteSize = ch.deferredWriteRing ? ch.deferredWriteRing->size() : 0;
  size_t deferredReadSize = ch.deferredReadRing ? ch.deferredReadRing->size() : 0;
  
  LOGF_I("SSH", "Channel %d Transfer Stats:", channelIndex);
  LOGF_I("SSH", "  - Total RX: %zu bytes, TX: %zu bytes", ch.totalBytesReceived, ch.totalBytesSent);
  LOGF_I("SSH", "  - Queued to Local: %zu, to Remote: %zu", ch.queuedBytesToLocal, ch.queuedBytesToRemote);
  LOGF_I("SSH", "  - Ring buffers: Write=%zu, Read=%zu", writeRingSize, readRingSize);
  LOGF_I("SSH", "  - Deferred buffers: Write=%zu, Read=%zu", deferredWriteSize, deferredReadSize);
  LOGF_I("SSH", "  - Lost chunks: %d, Consecutive errors: %d", ch.lostWriteChunks, ch.consecutiveErrors);
  
  // Calculer le ratio de duplication potentiel
  size_t totalQueued = ch.queuedBytesToLocal + ch.queuedBytesToRemote;
  size_t totalBuffered = writeRingSize + readRingSize + deferredWriteSize + deferredReadSize;
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
      (ch.writeRing->size() > 10 || ch.readRing->size() > 10) // Buffer activity
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
  // CORRECTION TEMPORAIRE: Désactiver la logique de queue pour éviter les interférences
  // Retourner toujours true mais avec vérification simple des canaux disponibles
  
  // Vérifier si on a atteint la limite de canaux
  int activeChannels = getActiveChannels();
  int maxChannels = config->getConnectionConfig().maxChannels;
  
  // Être moins restrictif - utiliser tous les canaux disponibles
  return activeChannels < maxChannels;
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
  
  // Initialiser les variables de détection des gros transferts
  channels[channelIndex].largeTransferInProgress = false;
  channels[channelIndex].transferStartTime = millis();
  channels[channelIndex].transferredBytes = 0;
  channels[channelIndex].peakBytesPerSecond = 0;

  libssh2_channel_set_blocking(channel, 0);

  LOGF_I("SSH", "Queued tunnel connection established (channel %d)", channelIndex);
  return true;
}