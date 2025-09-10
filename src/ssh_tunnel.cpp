#include "ssh_tunnel.h"
#include "network_optimizations.h"
#include "memory_fixes.h"
#include "lwip/sockets.h"

// Définir la taille de buffer pour les chunks de données
#define SSH_BUFFER_SIZE 1024

// Seuils de flow control optimisés (réduits) pour limiter l'accumulation et améliorer le backpressure
#undef HIGH_WATER_LOCAL
#undef LOW_WATER_LOCAL
#define HIGH_WATER_LOCAL (3 * 1024)      // 3KB - pause de lecture locale proactive
#define LOW_WATER_LOCAL  (2 * 1024)      // 2KB - reprise de lecture
#define CRITICAL_WATER_LOCAL (4 * 1024)  // 4KB - arrêt complet lectures socket local

// Paramètres d'écriture SSH
#define MAX_WRITES_PER_PASS 8
#define MIN_SSH_WINDOW_SIZE 512
#define MIN_WRITE_SIZE 256

// Buffer fixe (inchangé) + seuil d'intégrité canal
#define FIXED_BUFFER_SIZE (8 * 1024)
#define MAX_QUEUED_BYTES (32 * 1024)

SSHTunnel::SSHTunnel()
    : session(nullptr), listener(nullptr), socketfd(-1),
      state(TUNNEL_DISCONNECTED), lastKeepAlive(0), lastConnectionAttempt(0),
      reconnectAttempts(0), bytesReceived(0), bytesSent(0),
      channels(nullptr), rxBuffer(nullptr), txBuffer(nullptr),
      tunnelMutex(nullptr), statsMutex(nullptr), pendingConnectionsMutex(nullptr), 
      config(&globalSSHConfig), dataProcessingTask(nullptr), 
      dataProcessingSemaphore(nullptr), dataProcessingTaskRunning(false) {

  // OPTIMISÉ: Créer des mutex au lieu de sémaphores binaires pour de meilleures performances
  tunnelMutex = xSemaphoreCreateMutex();
  statsMutex = xSemaphoreCreateMutex();
  pendingConnectionsMutex = xSemaphoreCreateMutex();
  dataProcessingSemaphore = xSemaphoreCreateBinary();
  
  if (tunnelMutex == NULL || statsMutex == NULL || pendingConnectionsMutex == NULL || dataProcessingSemaphore == NULL) {
    LOG_E("SSH", "Failed to create tunnel mutexes");
  }
}

SSHTunnel::~SSHTunnel() {
  // Arrêter la tâche de traitement des données
  stopDataProcessingTask();
  
  disconnect();
  
  // Libérer les sémaphores
  SAFE_DELETE_SEMAPHORE(tunnelMutex);
  SAFE_DELETE_SEMAPHORE(statsMutex);
  SAFE_DELETE_SEMAPHORE(pendingConnectionsMutex);
  SAFE_DELETE_SEMAPHORE(dataProcessingSemaphore);
  
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
      // OPTIMISÉ: Nettoyer les nouveaux buffers unifiés
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
    channels[i].eagainErrors = 0; // NOUVEAU: Compteur séparé pour EAGAIN
    channels[i].queuedBytesToLocal = 0;
    channels[i].queuedBytesToRemote = 0;
    channels[i].lostWriteChunks = 0;
    
    // NOUVEAU: Initialiser les variables de détection des gros transferts
    channels[i].largeTransferInProgress = false;
    channels[i].transferStartTime = 0;
    channels[i].transferredBytes = 0;
    channels[i].peakBytesPerSecond = 0;
    
    // OPTIMISÉ: Créer les buffers unifiés (plus simples et efficaces)
    char ringName[32];
    
    // Buffer unifié pour SSH->Local (FIXED_BUFFER_SIZE = 8KB)
    snprintf(ringName, sizeof(ringName), "CH%d_SSH2LOC", i);
    channels[i].sshToLocalBuffer = new DataRingBuffer(FIXED_BUFFER_SIZE, ringName);
    
    // Buffer unifié pour Local->SSH (FIXED_BUFFER_SIZE = 8KB)
    snprintf(ringName, sizeof(ringName), "CH%d_LOC2SSH", i);
    channels[i].localToSshBuffer = new DataRingBuffer(FIXED_BUFFER_SIZE, ringName);
    
    if (!channels[i].sshToLocalBuffer || !channels[i].localToSshBuffer) {
      LOGF_E("SSH", "Failed to create unified buffers for channel %d", i);
      unlockTunnel();
      return false;
    }
    
    // OPTIMISÉ: Créer des mutex au lieu de sémaphores binaires
    channels[i].readMutex = xSemaphoreCreateMutex();
    channels[i].writeMutex = xSemaphoreCreateMutex();
    
    if (channels[i].readMutex == NULL || channels[i].writeMutex == NULL) {
      LOGF_E("SSH", "Failed to create mutexes for channel %d", i);
      unlockTunnel();
      return false;
    }
  }
  
  // Allouer les buffers avec vérification (utiliser la taille fixe)
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

  // NOUVEAU: Démarrer la tâche dédiée pour le traitement des données
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

  // OPTIMISÉ: Réduire la fréquence des logs dans la boucle chaude
  // Print statistics périodiques (toutes les 5 minutes au lieu de 2)
  static unsigned long lastStatsTime = 0;
  if (now - lastStatsTime > 300000) { // 5 minutes
    printChannelStatistics();
    lastStatsTime = now;
  }

  // NOUVEAU: Vérification de deadlock tous les 30 secondes (réduit)
  static unsigned long lastDeadlockCheck = 0;
  if (now - lastDeadlockCheck > 30000) { // 30 secondes
    checkAndRecoverDeadlocks();
    lastDeadlockCheck = now;
  }

  // Handle new connections
  handleNewConnection();
  
  // NOUVEAU: Traiter les connexions en attente si aucun gros transfert n'est actif
  if (!isLargeTransferActive()) {
    processPendingConnections();
  }

  // Handle data for existing channels (optimisé avec moins de logs)
  int maxChannels = config->getConnectionConfig().maxChannels;
  for (int i = 0; i < maxChannels; i++) {
    if (channels[i].active) {
      // OPTIMISÉ: Déléguer le traitement lourd à la tâche dédiée
      // Signaler la tâche de traitement qu'il y a du travail
      if (dataProcessingSemaphore) {
        xSemaphoreGive(dataProcessingSemaphore);
      }
      
      // Traitement léger dans la boucle principale
      handleChannelData(i);
    }
  }

  // Cleanup inactive channels
  cleanupInactiveChannels();
  
  // OPTIMISÉ: Augmenter légèrement le délai pour réduire la contention CPU
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
    // CORRECTION: Récupération immédiate des mutex bloqués au lieu d'attendre plusieurs erreurs
    LOGF_W("SSH", "Channel %d: Unhealthy detected, forcing immediate recovery", channelIndex);
    recoverChannel(channelIndex);
    
    // Vérifier si la récupération a réussi
    if (!isChannelHealthy(channelIndex)) {
      LOGF_E("SSH", "Channel %d: Recovery failed, closing channel", channelIndex);
      closeChannel(channelIndex);
      return;
    } else {
      LOGF_I("SSH", "Channel %d: Recovery successful, continuing", channelIndex);
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
    
    // Vérifier si tous les buffers unifiés sont vraiment vides
    bool allEmpty = (ch.sshToLocalBuffer ? ch.sshToLocalBuffer->empty() : true) && 
                   (ch.localToSshBuffer ? ch.localToSshBuffer->empty() : true);
    
    if (allEmpty) {
      LOGF_I("SSH", "Channel %d: Graceful close completed - all buffers empty", channelIndex);
      closeChannel(channelIndex);
    } else {
      // Log l'état des buffers unifiés pour diagnostic
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
  
  // Log détaillé pour le debugging avec les nouvelles statistiques
  LOGF_I("SSH", "Closing channel %d (session: %lums, rx: %d bytes, tx: %d bytes, errors: %d)", 
         channelIndex, sessionDuration, ch.totalBytesReceived, ch.totalBytesSent, ch.consecutiveErrors);

  // CORRECTION: Forcer la libération des mutex bloqués AVANT de nettoyer les données
  // Ceci résout le problème "Connection reset by peer" qui bloque le canal indéfiniment
  forceMutexRelease(channelIndex);

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
  
  // OPTIMISÉ: Reset des variables de détection des gros transferts et erreurs EAGAIN
  ch.largeTransferInProgress = false;
  ch.transferStartTime = 0;
  ch.transferredBytes = 0;
  ch.peakBytesPerSecond = 0;
  ch.eagainErrors = 0;
  
  // OPTIMISÉ: Vider les nouveaux buffers unifiés
  if (ch.sshToLocalBuffer) {
    ch.sshToLocalBuffer->clear();
    ch.queuedBytesToLocal = 0;
  }
  if (ch.localToSshBuffer) {
    ch.localToSshBuffer->clear();
    ch.queuedBytesToRemote = 0;
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
      
      // NOUVEAU: Vérifier et réparer les mutex bloqués AVANT toute autre vérification
      // Ceci résout le problème où un canal reste bloqué indéfiniment après "Connection reset by peer"
      if (!isChannelHealthy(i)) {
        LOGF_W("SSH", "Channel %d detected as unhealthy, attempting recovery", i);
        recoverChannel(i);
        // Donner une chance au canal récupéré
        continue;
      }
      
      // Nettoyage intelligent et moins agressif
      bool shouldClose = false;
      
      // Vérifier d'abord si le canal est en fermeture gracieuse
      if (channels[i].gracefulClosing) {
        // Forcer le traitement des données restantes
        processPendingData(i);
        
        // Permettre plus de temps pour vider les buffers unifiés
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
          // Log périodique de l'état pendant la fermeture gracieuse
          static unsigned long lastGracefulLog[16] = {0}; // Pour 16 canaux max
          if (now - lastGracefulLog[i] > 5000) { // Log toutes les 5 secondes
            LOGF_I("SSH", "Channel %d graceful close in progress - buffers: ssh2local=%zu, local2ssh=%zu", i,
                   channels[i].sshToLocalBuffer ? channels[i].sshToLocalBuffer->size() : 0,
                   channels[i].localToSshBuffer ? channels[i].localToSshBuffer->size() : 0);
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
        // Buffers unifiés trop pleins depuis trop longtemps
        else if (((channels[i].sshToLocalBuffer ? channels[i].sshToLocalBuffer->size() : 0) > 8192 || 
                  (channels[i].localToSshBuffer ? channels[i].localToSshBuffer->size() : 0) > 8192) && 
                 timeSinceActivity > 60000) {
          shouldClose = true;
          LOGF_W("SSH", "Channel %d has full buffers for %lums, closing", i, timeSinceActivity);
        }
        // Données anciennes dans les buffers unifiés (plus de 10 secondes)
        else if (!(channels[i].sshToLocalBuffer ? channels[i].sshToLocalBuffer->empty() : true) || 
                 !(channels[i].localToSshBuffer ? channels[i].localToSshBuffer->empty() : true)) {
          // Pour les buffers unifiés, traiter les données en attente
          if (timeSinceActivity > 10000) {
            LOGF_W("SSH", "Channel %d has old data in buffers, processing", i);
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
        totalQueued += (channels[i].sshToLocalBuffer ? channels[i].sshToLocalBuffer->size() : 0) + 
                      (channels[i].localToSshBuffer ? channels[i].localToSshBuffer->size() : 0);
      }
    }
    LOGF_I("SSH", "Channel status: %d active, %d total queued bytes", activeAfter, totalQueued);
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

// NOUVEAU: Méthode pour forcer la libération des mutex bloqués
void SSHTunnel::forceMutexRelease(int channelIndex) {
  if (channels == nullptr || channelIndex < 0 || channelIndex >= config->getConnectionConfig().maxChannels) {
    return;
  }
  
  TunnelChannel &ch = channels[channelIndex];
  
  LOGF_D("SSH", "Channel %d: Forcing mutex release", channelIndex);
  
  // Forcer la libération du read mutex
  if (ch.readMutex) {
    // Essayer d'acquérir avec timeout 0 pour vérifier l'état
    if (xSemaphoreTake(ch.readMutex, 0) == pdTRUE) {
      // Il était libre, le rendre
      xSemaphoreGive(ch.readMutex);
    } else {
      // Le mutex est bloqué, le détruire et le recréer
      LOGF_W("SSH", "Channel %d: Read mutex stuck, recreating", channelIndex);
      vSemaphoreDelete(ch.readMutex);
      ch.readMutex = xSemaphoreCreateMutex();
      if (!ch.readMutex) {
        LOGF_E("SSH", "Channel %d: Failed to recreate read mutex", channelIndex);
      }
    }
  }
  
  // Forcer la libération du write mutex
  if (ch.writeMutex) {
    // Essayer d'acquérir avec timeout 0 pour vérifier l'état
    if (xSemaphoreTake(ch.writeMutex, 0) == pdTRUE) {
      // Il était libre, le rendre
      xSemaphoreGive(ch.writeMutex);
    } else {
      // Le mutex est bloqué, le détruire et le recréer
      LOGF_W("SSH", "Channel %d: Write mutex stuck, recreating", channelIndex);
      vSemaphoreDelete(ch.writeMutex);
      ch.writeMutex = xSemaphoreCreateMutex();
      if (!ch.writeMutex) {
        LOGF_E("SSH", "Channel %d: Failed to recreate write mutex", channelIndex);
      }
    }
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
  size_t bufferSize = FIXED_BUFFER_SIZE; // Utiliser le buffer fixe au lieu d'adaptatif
  unsigned long now = millis();

  // OPTIMISÉ: Flow control avec high/low watermarks optimisés pour ESP32
  if (ch.flowControlPaused) {
    // Vérifier si on peut reprendre
    if (ch.queuedBytesToLocal < LOW_WATER_LOCAL) {
      ch.flowControlPaused = false;
      // Log seulement en mode DEBUG pour éviter le spam
      #ifdef DEBUG_FLOW_CONTROL
      LOGF_I("SSH", "Channel %d: Flow control RESUME (queuedToLocal=%zu)", 
             channelIndex, ch.queuedBytesToLocal);
      #endif
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

  // Backpressure critique : ne pas lire davantage si trop en attente
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
    // 1) Drainage en boucle des données déjà en queue (localToSshBuffer)
    size_t totalWritten = 0;
    int passes = 0;
    while (passes < MAX_WRITES_PER_PASS && ch.localToSshBuffer && !ch.localToSshBuffer->empty()) {
      // Vérifier fenêtre SSH
      size_t winSize = 0, winUsed = 0;
  // NOTE: libssh2_channel_window_write_ex signature semble différente sur cible; suppression contrôle fenêtre direct
  // (Future improvement: adapt according to actual header.)
  (void)winSize; (void)winUsed; // silencieux

      uint8_t temp[SSH_BUFFER_SIZE];
      size_t chunk = ch.localToSshBuffer->read(temp, sizeof(temp));
      if (chunk == 0) break;
      if (chunk < MIN_WRITE_SIZE && !ch.localToSshBuffer->empty()) {
        // Essayer d'agréger un peu plus pour éviter micro-write
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
          // Remettre le reste en tête (simple: réécrire) si possible
          ch.localToSshBuffer->write(temp + w, chunk - w);
        }
      } else if (w == LIBSSH2_ERROR_EAGAIN) {
        // Remettre le chunk entier
        ch.localToSshBuffer->write(temp, chunk);
        break;
      } else {
        ch.consecutiveErrors++;
        LOGF_W("SSH", "Channel %d: Write error %zd during drain", channelIndex, w);
        // Remettre les données pour réessai futur
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

    // 2) Lire le socket local si backpressure acceptable
    if (ch.queuedBytesToRemote < CRITICAL_WATER_LOCAL && isSocketReadable(ch.localSocket, 5)) {
      ssize_t localRead = recv(ch.localSocket, txBuffer, bufferSize, MSG_DONTWAIT);
      if (localRead > 0) {
        // Tentative écriture immédiate en boucle (drainage direct)
        size_t offset = 0; int directPass = 0; size_t directWrittenTotal = 0;
        while (offset < (size_t)localRead && directPass < MAX_WRITES_PER_PASS) {
          size_t remain = (size_t)localRead - offset;
          // Check window
            // (SSH window control disabled due to incorrect signature on target)
          ssize_t w = libssh2_channel_write_ex(ch.channel, 0, (char*)txBuffer + offset, remain);
          if (w > 0) {
            offset += w; directPass++; directWrittenTotal += w;
            ch.totalBytesSent += w; ch.lastSuccessfulWrite = now; ch.consecutiveErrors = 0;
            if (lockStats()) { bytesSent += w; unlockStats(); }
          } else if (w == LIBSSH2_ERROR_EAGAIN) {
            break; // Mettre le reste en file
          } else {
            ch.consecutiveErrors++; LOGF_W("SSH","Channel %d: Direct write err %zd",channelIndex,w); break;
          }
        }
        size_t remaining = (size_t)localRead - offset;
        if (remaining > 0) {
          if (queueData(channelIndex, txBuffer + offset, remaining, false)) {
            success = true;
          } else {
            LOGF_W("SSH","Channel %d: Failed to queue %zu residual bytes",channelIndex, remaining);
          }
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
  
  // CORRECTION: Espacer davantage les appels pour éviter la contention
  static unsigned long lastProcessTime[10] = {0};
  if (channelIndex < 10 && (now - lastProcessTime[channelIndex]) < 20) { // 20ms au lieu de 10ms
    return;
  }
  lastProcessTime[channelIndex] = now;
  
  // 1) Traiter le buffer SSH->Local (sshToLocalBuffer)
  if (xSemaphoreTake(ch.readMutex, pdMS_TO_TICKS(20)) == pdTRUE) {
    if (ch.sshToLocalBuffer && !ch.sshToLocalBuffer->empty() && 
        ch.localSocket >= 0 && isSocketWritable(ch.localSocket, 5)) {
      
      uint8_t tempBuffer[SSH_BUFFER_SIZE];
      size_t bytesRead = ch.sshToLocalBuffer->read(tempBuffer, sizeof(tempBuffer));
      
      if (bytesRead > 0) {
        ssize_t written = send(ch.localSocket, tempBuffer, bytesRead, MSG_DONTWAIT);

        if (written > 0) {
          ch.totalBytesReceived += written;
          ch.queuedBytesToLocal = (ch.queuedBytesToLocal > written) ? ch.queuedBytesToLocal - written : 0;
          if (lockStats()) { 
            bytesReceived += written; 
            unlockStats(); 
          }
          
          // Si pas tout envoyé, remettre le reste dans le buffer
          if (written < bytesRead) {
            ch.sshToLocalBuffer->write(tempBuffer + written, bytesRead - written);
          }
          
          LOGF_D("SSH", "Channel %d: Processed %zd/%zu bytes from SSH->Local buffer", 
                 channelIndex, written, bytesRead);
        } else if (written < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Socket temporairement non écrivable - remettre les données
            ch.sshToLocalBuffer->write(tempBuffer, bytesRead);
            LOGF_D("SSH", "Channel %d: Socket busy, %zu bytes preserved in SSH->Local buffer", 
                   channelIndex, bytesRead);
          } else {
            LOGF_W("SSH", "Channel %d: Error writing from SSH->Local buffer: %s", 
                   channelIndex, strerror(errno));
            ch.consecutiveErrors++;
          }
        } else {
          // written == 0 - socket fermé côté réception
          ch.sshToLocalBuffer->write(tempBuffer, bytesRead);
          LOGF_I("SSH", "Channel %d: Local socket closed, %zu bytes preserved", 
                 channelIndex, bytesRead);
        }
      }
    }
    xSemaphoreGive(ch.readMutex);
  }
  
  // 2) Traiter le buffer Local->SSH (localToSshBuffer)
  if (xSemaphoreTake(ch.writeMutex, pdMS_TO_TICKS(20)) == pdTRUE) {
    if (ch.localToSshBuffer && !ch.localToSshBuffer->empty() && ch.channel) {
      uint8_t tempBuffer[SSH_BUFFER_SIZE];
      size_t bytesRead = ch.localToSshBuffer->read(tempBuffer, sizeof(tempBuffer));
      
      if (bytesRead > 0) {
        ssize_t written = libssh2_channel_write(ch.channel, (char*)tempBuffer, bytesRead);

        if (written > 0) {
          ch.totalBytesSent += written;
          ch.queuedBytesToRemote = (ch.queuedBytesToRemote > written) ? ch.queuedBytesToRemote - written : 0;
          if (lockStats()) { 
            bytesSent += written; 
            unlockStats(); 
          }
          
          // Si pas tout envoyé, remettre le reste dans le buffer
          if (written < bytesRead) {
            ch.localToSshBuffer->write(tempBuffer + written, bytesRead - written);
          }
          
          LOGF_D("SSH", "Channel %d: Processed %zd/%zu bytes from Local->SSH buffer", 
                 channelIndex, written, bytesRead);
        } else if (written < 0) {
          if (written == LIBSSH2_ERROR_EAGAIN) {
            // Canal SSH temporairement occupé - remettre les données
            ch.localToSshBuffer->write(tempBuffer, bytesRead);
            LOGF_D("SSH", "Channel %d: SSH channel busy, %zu bytes preserved in Local->SSH buffer", 
                   channelIndex, bytesRead);
            ch.eagainErrors++;
          } else {
            LOGF_W("SSH", "Channel %d: Error writing from Local->SSH buffer: %zd", 
                   channelIndex, written);
            ch.consecutiveErrors++;
            // En cas d'erreur réelle, on peut décider de supprimer ces données
          }
        } else {
          // written == 0 - canal fermé
          ch.localToSshBuffer->write(tempBuffer, bytesRead);
          LOGF_I("SSH", "Channel %d: SSH channel closed, %zu bytes preserved", 
                 channelIndex, bytesRead);
        }
      }
    }
    xSemaphoreGive(ch.writeMutex);
  }

  // 3) Relancer le flow control si on est repassé sous le LOW watermark
  if (ch.flowControlPaused && ch.queuedBytesToLocal < LOW_WATER_LOCAL) {
    ch.flowControlPaused = false;
    LOGF_D("SSH", "Channel %d: Flow control resumed (below %d bytes)", channelIndex, LOW_WATER_LOCAL);
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
    return true; // Pas une erreur, juste rien à faire
  }
  
  if (size > SSH_BUFFER_SIZE) {
    // Traiter par fragments
    size = SSH_BUFFER_SIZE;
  }
  
  TunnelChannel &ch = channels[channelIndex];
  
  if (!ch.active) {
    return false; // Canal inactif, rejeter silencieusement
  }
  
  // OPTIMISÉ: Utiliser les nouveaux buffers unifiés selon la direction
  DataRingBuffer* targetBuffer = isRead ? ch.sshToLocalBuffer : ch.localToSshBuffer;
  
  // Sélectionner le bon mutex pour la synchronisation
  SemaphoreHandle_t mutex = isRead ? ch.readMutex : ch.writeMutex;
  
  // Protéger l'accès avec mutex (timeout 50ms réduit)
  if (xSemaphoreTake(mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
    ch.eagainErrors++; // Compter comme erreur EAGAIN
    return false;
  }
  
  // Vérifier fenêtre SSH avant d'enfiler pour direction Local->SSH
  if (!isRead && ch.channel) {
    size_t winSize = 0, winUsed = 0;
  // Window control disabled (incompatible signature) → TODO re-enable after header verification
  }

  // Écrire dans le buffer unifié
  size_t bytesWritten = targetBuffer->write(data, size);
  
  if (bytesWritten > 0) {
    // Succès - mettre à jour les statistiques
    if (isRead) {
      ch.queuedBytesToLocal += bytesWritten;
    } else {
      ch.queuedBytesToRemote += bytesWritten;
    }
    
    ch.lastActivity = millis();
    
    xSemaphoreGive(mutex);
    
    // Si il reste des données, les traiter récursivement
    if (bytesWritten < size) {
      return queueData(channelIndex, data + bytesWritten, size - bytesWritten, isRead);
    }
    
    return true;
  }
  
  // Buffer plein
  ch.lostWriteChunks++;
  if (ch.lostWriteChunks % 10 == 1) { // Log seulement chaque 10ème perte pour éviter le spam
    LOGF_W("SSH", "Channel %d: Buffer full - dropping data! Total lost chunks: %d", 
           channelIndex, ch.lostWriteChunks);
  }
  
  xSemaphoreGive(mutex);
  return false;
}

void SSHTunnel::flushPendingData(int channelIndex) {
  TunnelChannel &ch = channels[channelIndex];
  const TickType_t STANDARD_TIMEOUT = pdMS_TO_TICKS(100);
  const unsigned long GLOBAL_TIMEOUT_MS = 2000;

  unsigned long start = millis();
  int attempts = 0;
  bool dataRemaining = true;

  while (dataRemaining && (millis() - start) < GLOBAL_TIMEOUT_MS && attempts < 10) {
    attempts++;
    dataRemaining = false;

    bool readLocked = (ch.readMutex && xSemaphoreTake(ch.readMutex, STANDARD_TIMEOUT) == pdTRUE);
    bool writeLocked = (ch.writeMutex && xSemaphoreTake(ch.writeMutex, STANDARD_TIMEOUT) == pdTRUE);

    // Traiter Local->SSH (vider en écrivant tant que possible)
    if (writeLocked && ch.localToSshBuffer && ch.channel && !ch.localToSshBuffer->empty()) {
      uint8_t temp[SSH_BUFFER_SIZE];
      for (int pass = 0; pass < 3 && !ch.localToSshBuffer->empty(); pass++) {
        size_t got = ch.localToSshBuffer->read(temp, sizeof(temp));
        if (got == 0) break;
        ssize_t w = libssh2_channel_write_ex(ch.channel, 0, (char*)temp, got);
        if (w > 0) {
          ch.totalBytesSent += w;
          ch.queuedBytesToRemote = (ch.queuedBytesToRemote > (size_t)w) ? ch.queuedBytesToRemote - w : 0;
          if ((size_t)w < got) ch.localToSshBuffer->write(temp + w, got - w);
          dataRemaining = dataRemaining || !ch.localToSshBuffer->empty();
        } else if (w == LIBSSH2_ERROR_EAGAIN) {
          ch.localToSshBuffer->write(temp, got); // remettre
          dataRemaining = true; break;
        } else {
          ch.consecutiveErrors++; ch.localToSshBuffer->write(temp, got); break;
        }
      }
    }

    // Traiter SSH->Local (essayer d'envoyer au socket)
    if (readLocked && ch.sshToLocalBuffer && ch.localSocket >= 0 && !ch.sshToLocalBuffer->empty()) {
      uint8_t temp[SSH_BUFFER_SIZE];
      for (int pass = 0; pass < 3 && !ch.sshToLocalBuffer->empty(); pass++) {
        size_t got = ch.sshToLocalBuffer->read(temp, sizeof(temp));
        if (got == 0) break;
        ssize_t w = send(ch.localSocket, temp, got, MSG_DONTWAIT);
        if (w > 0) {
          ch.totalBytesReceived += w;
          ch.queuedBytesToLocal = (ch.queuedBytesToLocal > (size_t)w) ? ch.queuedBytesToLocal - w : 0;
          if ((size_t)w < got) ch.sshToLocalBuffer->write(temp + w, got - w);
          dataRemaining = dataRemaining || !ch.sshToLocalBuffer->empty();
        } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          ch.sshToLocalBuffer->write(temp, got); dataRemaining = true; break;
        } else if (w <= 0) {
          ch.consecutiveErrors++; ch.sshToLocalBuffer->write(temp, got); break;
        }
      }
    }

    if (writeLocked) xSemaphoreGive(ch.writeMutex);
    if (readLocked) xSemaphoreGive(ch.readMutex);

    if (dataRemaining) vTaskDelay(pdMS_TO_TICKS(50));
  }

  if (dataRemaining) {
    LOGF_W("SSH", "Channel %d: Flush incomplete after %d attempts (%lums)", channelIndex, attempts, millis() - start);
  } else {
    LOGF_I("SSH", "Channel %d: Flush completed in %d attempts (%lums)", channelIndex, attempts, millis() - start);
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
  LOGF_I("SSH", "  - Lost chunks: %d, Consecutive errors: %d, EAGAIN errors: %d", ch.lostWriteChunks, ch.consecutiveErrors, ch.eagainErrors);
  
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
    // Attendre un signal de travail ou timeout de 100ms
    if (xSemaphoreTake(dataProcessingSemaphore, pdMS_TO_TICKS(100)) == pdTRUE) {
      // Il y a du travail à faire
      if (!dataProcessingTaskRunning) break;
      
      int maxChannels = config->getConnectionConfig().maxChannels;
      for (int i = 0; i < maxChannels; i++) {
        if (channels[i].active) {
          // Traitement lourd des données en attente
          processPendingData(i);
          
          // Traitement supplémentaire pour les canaux en fermeture gracieuse
          if (channels[i].gracefulClosing) {
            processPendingData(i); // S'assurer que les données sont transmises
          }
          
          // Vérifier les gros transferts
          detectLargeTransfer(i);
        }
      }
    }
    
    // Petite pause pour éviter la surcharge CPU
    vTaskDelay(pdMS_TO_TICKS(5));
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
    tskIDLE_PRIORITY + 2, // Priorité légèrement élevée
    &dataProcessingTask
  );
  
  if (result != pdPASS) {
    LOG_E("SSH", "Failed to create data processing task");
    dataProcessingTaskRunning = false;
    return false;
  }
  
  LOG_I("SSH", "Data processing task started successfully");
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

