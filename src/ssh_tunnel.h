#ifndef SSH_TUNNEL_H
#define SSH_TUNNEL_H

#include <libssh2_esp.h>
#include "ssh_config.h"
#include "logger.h"
#include "memory_fixes.h"
#include "ring_buffer.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include "lwip/netdb.h"
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <vector>

enum TunnelState {
    TUNNEL_DISCONNECTED = 0,
    TUNNEL_CONNECTING = 1,
    TUNNEL_CONNECTED = 2,
    TUNNEL_ERROR = 3
};

struct TunnelChannel {
    // Compteur de chunks perdus côté Local->SSH (diagnostic)
    int lostWriteChunks;
    LIBSSH2_CHANNEL* channel;
    bool active;
    int localSocket; // Local socket for this channel
    unsigned long lastActivity;
    size_t pendingBytes; // Données en attente d'écriture
    bool flowControlPaused; // Pause temporaire pour éviter la congestion
    SemaphoreHandle_t readMutex; // Protection thread-safe pour la lecture (mutex)
    SemaphoreHandle_t writeMutex; // Protection thread-safe pour l'écriture (mutex)
    
    // OPTIMISÉ: Un seul buffer circulaire par direction (supprime duplication ring+deferred)
    DataRingBuffer* sshToLocalBuffer;   // SSH->Local (unifié)
    DataRingBuffer* localToSshBuffer;   // Local->SSH (unifié)
    
    // Statistiques et contrôle
    size_t totalBytesReceived; // Statistiques par canal
    size_t totalBytesSent;
    unsigned long lastSuccessfulWrite; // Dernière écriture réussie
    unsigned long lastSuccessfulRead;  // Dernière lecture réussie
    bool gracefulClosing; // Fermeture en cours mais avec données restantes
    int consecutiveErrors; // Nombre d'erreurs consécutives
    int eagainErrors; // NOUVEAU: Compteur séparé pour erreurs EAGAIN
    
    // Compteurs supplémentaires pour gestion fine du flow control
    size_t queuedBytesToLocal;   // Bytes dans sshToLocalBuffer
    size_t queuedBytesToRemote;  // Bytes dans localToSshBuffer
    
    // NOUVEAU: Détection des gros transferts
    bool largeTransferInProgress; // Transfert de gros fichier en cours
    unsigned long transferStartTime; // Début du transfert actuel
    size_t transferredBytes;      // Bytes transférés dans ce transfert
    size_t peakBytesPerSecond;    // Pic de débit pour ce canal
};

class SSHTunnel {
public:
    SSHTunnel();
    ~SSHTunnel();
    
    bool init();
    bool connectSSH();
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
    bool verifyHostKey();
    bool createReverseTunnel();
    void cleanupSSH();

    // Channel management
    bool handleNewConnection();
    void handleChannelData(int channelIndex);
    void closeChannel(int channelIndex);
    void cleanupInactiveChannels();
    void printChannelStatistics();

    // Nouvelles méthodes pour améliorer la fiabilité
    bool processChannelRead(int channelIndex);  // SSH -> Local
    bool processChannelWrite(int channelIndex); // Local -> SSH (poll pour écriture)
    void processPendingData(int channelIndex);  // Traiter les données en attente (poll pour lecture/écriture)
    bool queueData(int channelIndex, uint8_t* data, size_t size, bool isRead);
    void flushPendingData(int channelIndex);
    bool isChannelHealthy(int channelIndex);
    void recoverChannel(int channelIndex);
    void gracefulRecoverChannel(int channelIndex); // NOUVEAU: Récupération sans effacer les buffers
    size_t getOptimalBufferSize(int channelIndex);
    void checkAndRecoverDeadlocks(); // NOUVEAU: Détection et récupération des deadlocks
    
    // NOUVEAU: Tâche dédiée pour traitement des données (pattern producer/consumer)
    static void dataProcessingTaskWrapper(void* parameter);
    void dataProcessingTaskFunction();
    bool startDataProcessingTask();
    void stopDataProcessingTask();
    
    // NOUVEAU: Diagnostic de duplication de données
    void printDataTransferStats(int channelIndex);
    
    // NOUVEAU: Gestion des gros transferts et file d'attente des connexions
    bool isLargeTransferActive();
    void detectLargeTransfer(int channelIndex);
    bool shouldAcceptNewConnection();
    void queuePendingConnection(LIBSSH2_CHANNEL* channel);
    bool processPendingConnections();
    bool processQueuedConnection(LIBSSH2_CHANNEL* channel);

    // Poll helpers
    bool isSocketWritable(int sockfd, int timeoutMs = 0);
    bool isSocketReadable(int sockfd, int timeoutMs = 0);

    // Connection monitoring
    void sendKeepAlive();
    bool checkConnection();
    void handleReconnection();

    // Utility functions
    static int socketCallback(LIBSSH2_SESSION* session, libssh2_socket_t fd, void** abstract);

    // Member variables
    LIBSSH2_SESSION* session;
    LIBSSH2_LISTENER* listener;
    int socketfd;

    TunnelChannel* channels; // Allocation dynamique basée sur la config

    TunnelState state;
    unsigned long lastKeepAlive;
    unsigned long lastConnectionAttempt;
    int reconnectAttempts;

    // Statistics
    unsigned long bytesReceived;
    unsigned long bytesSent;

    // Buffers (allocation dynamique basée sur la config)
    uint8_t* rxBuffer;
    uint8_t* txBuffer;

    // Protection thread-safe
    SemaphoreHandle_t tunnelMutex;
    SemaphoreHandle_t statsMutex;

    // Configuration reference
    SSHConfiguration* config;
    
    // NOUVEAU: File d'attente pour les connexions en attente pendant les gros transferts
    struct PendingConnection {
        LIBSSH2_CHANNEL* channel;
        unsigned long timestamp;
    };
    std::vector<PendingConnection> pendingConnections;
    SemaphoreHandle_t pendingConnectionsMutex;
    
    // OPTIMISÉ: Seuils pour la détection des gros transferts et flow control
    static const size_t LARGE_TRANSFER_THRESHOLD = 100 * 1024;  // 100KB
    static const size_t LARGE_TRANSFER_RATE_THRESHOLD = 15 * 1024; // 15KB/s
    static const unsigned long LARGE_TRANSFER_TIME_THRESHOLD = 3000; // 3 secondes
    
    // OPTIMISÉ: Nouveaux seuils de flow control plus élevés
    static const size_t HIGH_WATER_LOCAL = 28 * 1024;  // 28KB (augmenté)
    static const size_t LOW_WATER_LOCAL = 14 * 1024;   // 14KB (50% de HIGH_WATER)
    static const size_t FIXED_BUFFER_SIZE = 8 * 1024;  // Buffer fixe 8KB
    
    // NOUVEAU: Tâche dédiée pour le traitement des données
    TaskHandle_t dataProcessingTask;
    SemaphoreHandle_t dataProcessingSemaphore;
    bool dataProcessingTaskRunning;

    // Méthodes de protection
    bool lockTunnel();
    void unlockTunnel();
    bool lockStats();
    void unlockStats();

    // Méthodes de protection par canal avec mutex séparés
    bool lockChannelRead(int channelIndex);
    void unlockChannelRead(int channelIndex);
    bool lockChannelWrite(int channelIndex);
    void unlockChannelWrite(int channelIndex);

    // Méthodes de compatibilité (deprecated)
    bool lockChannel(int channelIndex);
    void unlockChannel(int channelIndex);
    
    // NOUVEAU: Méthode pour forcer la libération des mutex bloqués
    void forceMutexRelease(int channelIndex);
};

#endif